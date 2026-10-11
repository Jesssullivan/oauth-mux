"""Fixed two-public-file Yoga receiver; no archive execution or install authority."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

PARENT = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'
EPOCH = '25a0acfd-8ba2-46d2-ac33-c99973b25eee'
ARCHIVE = 'output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz'
FILES = (
    (ARCHIVE, 59809170, '7455b2b6185b7625f0349c226fe80fec6a3ade6c44f2762f75a34fb90bfb7331'),
    ('receipt.json', 22772, 'c5f96069b6e6037b35c5d6101d1442dde7bdcdd8193b4422af9fb50ab65d5638'),
)
PYTHON = '/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12/bin/python3.13'
SYSTEMD_RUN = '/nix/store/9rpism89x6lyjcwzzkp6kana25rs03nn-systemd-260.1/bin/systemd-run'
SYSTEMCTL = '/nix/store/9rpism89x6lyjcwzzkp6kana25rs03nn-systemd-260.1/bin/systemctl'
TOOLS = (PYTHON, SYSTEMD_RUN, SYSTEMCTL)
SCOPE = 'omux-yoga-two-public-install-inputs-v1'
FIXED_ENV={'PATH':'','HOME':'/.omux-unavailable','LANG':'C','LC_ALL':'C',
           'PYTHONNOUSERSITE':'1'}
UNSET=('LD_PRELOAD','LD_LIBRARY_PATH','LD_AUDIT','PYTHONPATH','PYTHONHOME','PYTHONSTARTUP',
       'SSH_AUTH_SOCK','SSH_CONNECTION','SSH_CLIENT','SSH_TTY','SYSTEMD_BUS_ADDRESS',
       'SYSTEMD_HOST','SYSTEMD_MACHINE','DBUS_SYSTEM_BUS_ADDRESS','DBUS_SESSION_BUS_ADDRESS',
       'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy',
       'all_proxy','no_proxy','NIX_REMOTE','NIX_PATH','NIX_CONFIG')
MAX_NS = 1200 * 10**9
RESERVE_NS = 30 * 10**9
FRAME = 65536
CAPS = {'MemoryMax': '268435456', 'MemorySwapMax': '0', 'TasksMax': '32'}
UUID = re.compile('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
SHOW = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'ControlGroup',
        'ExecMainStatus', 'Result', 'Slice', 'MemoryMax', 'MemorySwapMax', 'TasksMax',
        'CPUQuotaPerSecUSec', 'RuntimeMaxUSec', 'TimeoutStopUSec', 'PrivateNetwork', 'NoNewPrivileges',
        'ProtectSystem', 'ProtectHome', 'ReadWritePaths', 'KillMode', 'InvocationID', 'Transient', 'RemainAfterExit', 'Environment', 'UnsetEnvironment')

def require(value, cause):
    if not value:
        raise ValueError(cause)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

def decode(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate-field')
            value[key] = item
        return value
    return json.loads(data, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite-field')))

def tick(deadline):
    require(type(deadline) is int and deadline > time.monotonic_ns(), 'original-clock-exhausted')
    return (deadline - time.monotonic_ns()) / 10**9

def freeze_clock(remote_timestamp, root_entry, root_deadline, root_before, root_after):
    """T occurred inside [R0,R1]; translate remaining interval, never clock epochs."""
    values = (remote_timestamp, root_entry, root_deadline, root_before, root_after)
    require(all(type(value) is int and value > 0 for value in values)
            and root_deadline - root_entry == MAX_NS
            and root_entry <= root_before <= root_after < root_deadline,
            'cross-clock-binding')
    remaining = root_deadline - root_after
    require(remaining > 2*RESERVE_NS + 5 * 10**9, 'cross-clock-reserve')
    return remote_timestamp + remaining - 2*RESERVE_NS

def validate_remote_clock(timestamp, deadline):
    require(type(timestamp) is int and type(deadline) is int
            and timestamp > 0 and 5 * 10**9 < deadline - timestamp <= MAX_NS - 2*RESERVE_NS
            and timestamp <= time.monotonic_ns(), 'frozen-remote-clock')
    tick(deadline)
    return deadline

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)

def file_identity(info):
    return identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

class Directory:
    """Complete physical named and held ancestry, not only a final pathname."""
    def __init__(self, path, deadline, *, leaf_private=False, immutable_tool=False):
        path = Path(path)
        require(path.is_absolute() and '..' not in path.parts and len(path.parts) <= 32,
                'physical-directory-shape')
        self.path, self.deadline, self.fds, self.pins = path, deadline, [], []
        try:
            self.fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
            root = os.fstat(self.fds[-1])
            require(root.st_uid == 0 and not root.st_mode & 0o022, 'physical-root-owner')
            self.pins.append(identity(root))
            for part in path.parts[1:]:
                tick(deadline)
                self.fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=self.fds[-1]))
                info = os.fstat(self.fds[-1])
                require(info.st_uid in (0, os.getuid()) and
                        (not info.st_mode & 0o022 or immutable_tool
                         and str(Path(*path.parts[:len(self.fds)])) == '/nix/store'
                         and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1775),
                        'physical-directory-owner')
                self.pins.append(identity(info))
            if leaf_private:
                info = os.fstat(self.fds[-1])
                require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                        'private-directory-owner')
            self.check()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.fds[-1]

    def check(self):
        for index, fd in enumerate(self.fds):
            tick(self.deadline)
            named = (os.lstat('/') if index == 0 else
                     os.stat(self.path.parts[index], dir_fd=self.fds[index-1], follow_symlinks=False))
            require(identity(os.fstat(fd)) == self.pins[index] == identity(named),
                    'physical-directory-rebound')

    def close(self):
        fds, self.fds = self.fds, []
        failed = False
        for fd in reversed(fds):
            try:
                os.close(fd)
            except BaseException:
                failed = True
        require(not failed, 'directory-release-incomplete')

def absent(parent):
    try:
        os.stat(EPOCH, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError:
        parent.check()
        return
    raise ValueError('selected-epoch-already-present')

def write_all(fd, data, deadline):
    view = memoryview(data)
    while view:
        tick(deadline)
        try:
            count = os.write(fd, view)
        except BlockingIOError:
            wait(fd, selectors.EVENT_WRITE, deadline)
            continue
        require(count > 0, 'short-write')
        view = view[count:]

def wait(fd, event, deadline):
    with selectors.DefaultSelector() as selector:
        selector.register(fd, event)
        while not selector.select(min(1.0, tick(deadline))):
            tick(deadline)

def exact(fd, count, deadline):
    require(type(count) is int and 0 < count <= FRAME, 'frame-bound')
    result = bytearray()
    while len(result) < count:
        tick(deadline)
        try:
            data = os.read(fd, count - len(result))
        except BlockingIOError:
            wait(fd, selectors.EVENT_READ, deadline)
            continue
        require(data, 'stream-eof')
        result.extend(data)
    return bytes(result)

def line(fd, deadline):
    result = bytearray()
    while not result.endswith(b'\n'):
        require(len(result) < 16384, 'metadata-frame-bound')
        result.extend(exact(fd, 1, deadline))
    return decode(bytes(result))

def emit(fd, value, deadline):
    data = canonical(value) + b'\n'
    require(len(data) <= 16384, 'metadata-frame-bound')
    write_all(fd, data, deadline)

def hash_leaf(parent_fd, name, size, digest, deadline, mode):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == mode
                and info.st_size == size, 'fixed-public-leaf-custody')
        actual, count = hashlib.sha256(), 0
        while True:
            tick(deadline)
            data = os.read(fd, FRAME)
            if not data:
                break
            count += len(data)
            require(count <= size, 'fixed-public-leaf-size')
            actual.update(data)
        require(count == size and actual.hexdigest() == digest
                and file_identity(info) == file_identity(os.fstat(fd))
                == file_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                'fixed-public-leaf-digest')
        return file_identity(info)
    finally:
        os.close(fd)

class Transaction:
    """Only this invocation's new exact tree can be written or removed."""
    def __init__(self, deadline):
        self.deadline, self.cleanup_deadline = deadline, deadline + RESERVE_NS
        self.parent, self.created, self.dirs, self.leaves = None, [], [], []
        self.published = False
        try:
            self.parent = Directory(PARENT, deadline)
            absent(self.parent)
            free = os.fstatvfs(self.parent.fd)
            require(free.f_bavail * free.f_frsize >= 2 * sum(row[1] for row in FILES),
                    'fixed-public-space')
        except BaseException:
            self.close()
            raise

    def mkdir(self, parent, name):
        tick(self.deadline)
        os.mkdir(name, 0o700, dir_fd=parent)
        # Record the operation before the fallible capture. An uncaptured new
        # directory makes cleanup fail closed; it is never silently deleted.
        self.created.append([parent, name, None])
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'created-directory-custody')
        self.created[-1][2] = identity(info)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        self.dirs.append((name, fd, identity(info)))
        require(identity(os.fstat(fd)) == identity(info), 'created-directory-rebound')

    def create(self):
        self.parent.check()
        absent(self.parent)
        self.mkdir(self.parent.fd, EPOCH)
        for part in Path(ARCHIVE).parts[:-1]:
            self.mkdir(self.dirs[-1][1], part)
        self.check()

    def check(self):
        self.parent.check()
        for parent, name, pin in self.created:
            tick(self.deadline)
            require(pin is not None and pin ==
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'new-public-directory-rebound')
        for _, fd, pin in self.dirs:
            require(identity(os.fstat(fd)) == pin, 'new-public-directory-held')

    def receive(self, incoming):
        self.create()
        for relative, size, digest in FILES:
            self.check()
            metadata = line(incoming, self.deadline)
            require(metadata == {'role': relative, 'bytes': size, 'sha256': digest}
                    and type(metadata.get('bytes')) is int, 'fixed-two-role-frame')
            parent = self.dirs[-1][1] if relative == ARCHIVE else self.dirs[0][1]
            name, temporary = Path(relative).name, '.' + Path(relative).name + '.receiving'
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            leaf = {'parent': parent, 'names': [temporary], 'fd': fd, 'pin': None}
            self.leaves.append(leaf)
            leaf['pin'] = identity(os.fstat(fd))
            left, actual = size, hashlib.sha256()
            while left:
                data = exact(incoming, min(FRAME, left), self.deadline)
                actual.update(data)
                write_all(fd, data, self.deadline)
                left -= len(data)
            require(actual.hexdigest() == digest, 'fixed-two-role-digest')
            os.fsync(fd)
            require(identity(os.fstat(fd)) == leaf['pin'] ==
                    identity(os.stat(temporary, dir_fd=parent, follow_symlinks=False)),
                    'new-leaf-rebound')
            os.fchmod(fd, 0o400)
            leaf['pin'] = identity(os.fstat(fd))
            hash_leaf(parent, temporary, size, digest, self.deadline, 0o400)
            self.check()
            # Atomic NO-REPLACE publication. Receipt is the second/final role;
            # neither a partial archive nor partial receipt has its final name.
            os.link(temporary, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            leaf['names'].append(name)
            require(os.fstat(fd).st_nlink == 2 and leaf['pin'] ==
                    identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    'published-leaf-rebound')
            os.unlink(temporary, dir_fd=parent)
            leaf['names'].remove(temporary)
            os.fsync(parent)
            hash_leaf(parent, name, size, digest, self.deadline, 0o400)
        require(line(incoming, self.deadline) == {'end': SCOPE}, 'fixed-two-role-end')
        self.readback()
        self.published = True
        return {'scope': SCOPE, 'files': 2, 'bytes': sum(row[1] for row in FILES),
                'destination_rehashed': True, 'installation': False, 'ready': False}

    def readback(self):
        self.check()
        require(set(os.listdir(self.dirs[0][1])) == {'output-base', 'receipt.json'}, 'new-root-extra')
        for index, (_, fd, _) in enumerate(self.dirs[1:]):
            expected = {self.dirs[index + 2][0]} if index + 2 < len(self.dirs) else {Path(ARCHIVE).name}
            require(set(os.listdir(fd)) == expected, 'new-directory-extra')
        for relative, size, digest in FILES:
            parent = self.dirs[-1][1] if relative == ARCHIVE else self.dirs[0][1]
            hash_leaf(parent, Path(relative).name, size, digest, self.deadline, 0o400)
        self.check()

    def close(self):
        self.deadline = self.cleanup_deadline
        if self.parent is not None:
            self.parent.deadline = self.cleanup_deadline
        failed = False
        if self.created and not self.published:
            try:
                self.check()
                for leaf in reversed(self.leaves):
                    for name in reversed(leaf['names']):
                        require(leaf['pin'] is not None and identity(os.fstat(leaf['fd'])) == leaf['pin'] ==
                                identity(os.stat(name, dir_fd=leaf['parent'], follow_symlinks=False)),
                                'cleanup-leaf-rebound')
                        os.unlink(name, dir_fd=leaf['parent'])
                for parent, name, pin in reversed(self.created):
                    tick(self.cleanup_deadline)
                    require(pin is not None and pin ==
                            identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                            'cleanup-directory-rebound')
                    os.rmdir(name, dir_fd=parent)
            except BaseException:
                failed = True
        for leaf in self.leaves:
            try:
                os.close(leaf['fd'])
            except BaseException:
                failed = True
        for _, fd, _ in reversed(self.dirs):
            try:
                os.close(fd)
            except BaseException:
                failed = True
        if self.parent is not None:
            try:
                self.parent.close()
            except BaseException:
                failed = True
        self.leaves, self.dirs, self.created, self.parent = [], [], [], None
        require(not failed, 'transaction-release-incomplete')

def properties(data,fields=SHOW):
    result = {}
    for row in data.decode('ascii').splitlines():
        require('=' in row, 'manager-property-frame')
        key, value = row.split('=', 1)
        require(key in fields and key not in result, 'manager-property-key')
        result[key] = value
    require(set(result) == set(fields), 'manager-property-incomplete')
    return result

def duration(value):
    from decimal import Decimal
    scales = {'us': 1, 'ms': 1000, 's': 1000000, 'min': 60000000, 'h': 3600000000}
    matches = list(re.finditer(r'([0-9]+(?:\.[0-9]{1,6})?)(us|ms|s|min|h)', value))
    require(matches and ''.join(item.group(0) for item in matches) == value.replace(' ', ''),
            'manager-duration')
    return sum(Decimal(item.group(1)) * scales[item.group(2)] for item in matches)

def unit_name(token):
    require(type(token) is str and UUID.fullmatch(token), 'fixed-action-uuid')
    return 'omux-yoga-install-inputs-' + token + '.service'

def verify_unit(value, token, runtime_us):
    require(value['Id'] == unit_name(token) and value['LoadState'] == 'loaded'
            and value['ActiveState'] == 'active' and value['SubState'] == 'running'
            and re.fullmatch('[1-9][0-9]*', value['MainPID'])
            and value['ControlGroup'] == '/user.slice/user-' + str(os.getuid()) +
                '.slice/user@' + str(os.getuid()) + '.service/app.slice/' + unit_name(token)
            and value['Slice'] == 'app.slice' and all(value[key] == expected for key, expected in CAPS.items())
            and duration(value['CPUQuotaPerSecUSec']) == 100000
            and 0 < duration(value['RuntimeMaxUSec']) <= runtime_us
            and duration(value['TimeoutStopUSec']) == 5000000
            and value['PrivateNetwork'] == value['NoNewPrivileges'] == 'yes'
            and value['ProtectSystem'] == 'strict' and value['ProtectHome'] == 'yes'
            and value['ReadWritePaths'] == PARENT and value['KillMode'] == 'control-group'
            and value['Transient'] == value['RemainAfterExit'] == 'yes'
            and re.fullmatch('[0-9a-f]{32}', value['InvocationID'])
            and value['InvocationID'] != '0' * 32
            and set(value['UnsetEnvironment'].split()) == set(UNSET)
            and dict(item.split('=',1) for item in value['Environment'].split()) == FIXED_ENV,
            'receiver-effective-properties')
    return int(value['MainPID']), value['ControlGroup']

def process(pid):
    require(type(pid) is int and pid > 1, 'receiver-process-pid')
    root = '/proc/' + str(pid)
    info = os.stat(root, follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid(), 'receiver-process-owner')
    fd = os.open(root + '/stat', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        data = os.read(fd, 4097)
        require(0 < len(data) <= 4096 and os.read(fd, 1) == b'', 'receiver-process-stat')
    finally:
        os.close(fd)
    tail = data.rsplit(b') ', 1)[1].split()
    require(int(data.split(b' ', 1)[0]) == pid and len(tail) >= 20 and int(tail[19]) > 0,
            'receiver-process-start')
    return (pid, int(tail[19]), info.st_uid)

def worker(token, deadline):
    unit_name(token)
    tick(deadline)
    os.set_blocking(0, False)
    os.set_blocking(1, False)
    import signal
    def cancelled(signum, frame):
        raise ValueError('receiver-cancelled')
    for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(signum, cancelled)
    require(line(0, deadline) == {'go': token, 'scope': SCOPE}, 'receiver-go-required')
    transaction = Transaction(deadline)
    try:
        projection = transaction.receive(0)
        emit(1, dict(projection, phase='worker-readback'), deadline)
    finally:
        transaction.deadline = deadline + RESERVE_NS
        if transaction.parent is not None:
            transaction.parent.deadline = transaction.deadline
        transaction.close()

def worker_code(token, deadline, source):
    unit_name(token)
    require(type(source) is str and 0 < len(source.encode('utf8')) <= 256*1024,
            'fixed-public-receiver-source')
    return source + '\ntry:\n worker(' + repr(token) + ',' + str(deadline) + ')\nexcept BaseException:\n sys.exit(125)\n'

def receiver_process(pid, token, work_deadline, source, observation_deadline):
    """Only the captured submitted receiver's public argv may be observed."""
    pin = process(pid)
    executable = '/proc/' + str(pid) + '/exe'
    tick(observation_deadline)
    require(os.readlink(executable) == PYTHON, 'submitted-receiver-executable')
    expected = b'\0'.join(os.fsencode(item) for item in
        (PYTHON, '-I', '-S', '-c', worker_code(token, work_deadline, source))) + b'\0'
    require(len(expected) <= 320*1024, 'submitted-public-argv-bound')
    fd = os.open('/proc/' + str(pid) + '/cmdline',
                 os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        chunks, size = [], 0
        while size <= len(expected):
            tick(observation_deadline)
            chunk = os.read(fd, min(FRAME, len(expected)+1-size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        require(b''.join(chunks) == expected and process(pid) == pin
                and os.readlink(executable) == PYTHON, 'submitted-receiver-command')
        tick(observation_deadline)
        return pin
    finally:
        os.close(fd)

def cgroup_pin(path, pid, deadline):
    require(type(path) is str and path.startswith('/user.slice/')
            and '..' not in Path(path).parts, 'receiver-cgroup-path')
    directory = Directory('/sys/fs/cgroup' + path, deadline)
    directory.events = directory.procs = None
    try:
        values = {}
        for name in ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max', 'cgroup.procs'):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
            try:
                data = os.read(fd, 4097)
                require(len(data) <= 4096 and os.read(fd, 1) == b'', 'receiver-cgroup-bound')
                values[name] = data.decode('ascii').strip()
            finally:
                os.close(fd)
        require(values['memory.max'] == CAPS['MemoryMax'] and values['memory.swap.max'] == '0'
                and values['pids.max'] == '32' and values['cpu.max'] == '10000 100000'
                and values['cgroup.procs'] == str(pid), 'receiver-effective-cgroup')
        directory.check()
        directory.events = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                   dir_fd=directory.fd)
        directory.procs = os.open('cgroup.procs', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                  dir_fd=directory.fd)
        return directory
    except BaseException:
        primary = sys.exc_info()[1]
        failed = False
        for fd in (directory.events, directory.procs):
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException:
                    failed = True
        try:
            directory.close()
        except BaseException:
            failed = True
        if failed:
            primary.add_note('receiver-cgroup-release-incomplete')
        raise

def session_peer(deadline):
    import socket
    import struct
    path = '/run/user/' + str(os.getuid()) + '/systemd/private'
    parent = Directory(str(Path(path).parent), deadline, leaf_private=True)
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        info = os.stat(Path(path).name, dir_fd=parent.fd, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
                and info.st_gid == os.getgid(), 'local-manager-socket')
        stream.settimeout(min(2, tick(deadline)))
        stream.connect(path)
        pid, uid, gid = struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(uid == os.getuid() and pid > 1, 'local-manager-peer-user')
        actual = process(pid)
        parent.check()
        require(identity(info) == identity(os.stat(Path(path).name, dir_fd=parent.fd,
                                                 follow_symlinks=False)), 'local-manager-socket-rebound')
        return actual, identity(info)
    finally:
        stream.close()
        parent.close()

def manager_environment():
    # A fixed LOCAL user manager, independent of ambient remote bus selectors.
    runtime = '/run/user/' + str(os.getuid())
    return {'PATH': '', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/.omux-unavailable',
            'XDG_RUNTIME_DIR': runtime, 'DBUS_SESSION_BUS_ADDRESS': 'unix:path=' + runtime + '/bus',
            'SYSTEMD_PAGER': 'cat', 'SYSTEMD_COLORS': '0'}

def bounded(command, deadline, maximum=32768, *, accept=(0,), cleanup_deadline=None, return_status=False):
    cleanup_deadline = deadline + RESERVE_NS if cleanup_deadline is None else cleanup_deadline
    tick(deadline)
    child = None
    try:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=manager_environment())
        output, error = child.communicate(timeout=tick(deadline))
        require(len(output) <= maximum and len(error) <= 4096 and child.returncode in accept and not error,
                'fixed-manager-operation-refused')
        tick(deadline)
        return (child.returncode,output) if return_status else output
    finally:
        if child is not None:
            primary = sys.exc_info()[1]
            failure = False
            try:
                if child.poll() is None:
                    child.kill()
            except BaseException:
                failure = True
            try:
                child.wait(timeout=max(0.001, tick(cleanup_deadline)))
            except BaseException:
                failure = True
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException:
                        failure = True
            if failure:
                if primary is not None:
                    primary.add_note('manager-child-cleanup-incomplete')
                else:
                    raise ValueError('manager-child-cleanup-incomplete')

def show(token, deadline, *, missing=False, cleanup_deadline=None):
    status, raw = bounded([SYSTEMCTL, '--user', 'show', unit_name(token),
                           '--property=' + ','.join(SHOW)], deadline,
                          accept=(0, 4) if missing else (0,),
                          cleanup_deadline=cleanup_deadline, return_status=True)
    value = properties(raw)
    require(status == 0 or missing and status == 4 and value['LoadState'] == 'not-found',
            'receiver-unit-error-status')
    return value

def receiver_command(token, deadline, source):
    tick(deadline)
    seconds = math.floor(tick(deadline))
    require(seconds > 5, 'receiver-start-reserve')
    properties_ = [
        'RemainAfterExit=yes', 'MemoryMax=268435456', 'MemorySwapMax=0', 'TasksMax=32', 'CPUQuota=10%',
        'RuntimeMaxSec=' + str(seconds + 25), 'TimeoutStopSec=5', 'KillMode=control-group',
        'PrivateNetwork=yes', 'NoNewPrivileges=yes', 'ProtectSystem=strict', 'ProtectHome=yes',
        'ReadWritePaths=' + PARENT, 'UMask=0077', 'RestrictAddressFamilies=AF_UNIX',
        'PrivateTmp=yes', 'ProtectProc=invisible', 'ProcSubset=pid',
        'UnsetEnvironment='+' '.join(UNSET),
        'Environment='+' '.join(key+'='+value for key,value in FIXED_ENV.items()),
    ]
    code = worker_code(token, deadline, source)
    return [SYSTEMD_RUN, '--user', '--quiet', '--wait', '--pipe', '--service-type=exec',
            '--unit=' + unit_name(token), '--slice=app.slice',
            *[item for value in properties_ for item in ('--property', value)],
            '--', PYTHON, '-I', '-S', '-c', code], (seconds + 25) * 1000000

def destination_readback(deadline):
    parent = Directory(PARENT, deadline)
    held = []
    try:
        path = Path(PARENT) / EPOCH
        epoch = Directory(path, deadline, leaf_private=True)
        held.append(epoch)
        require(set(os.listdir(epoch.fd)) == {'output-base', 'receipt.json'}, 'destination-extra')
        current = epoch
        parts = Path(ARCHIVE).parts
        for index, name in enumerate(parts[:-1]):
            current = Directory(path.joinpath(*parts[:index+1]), deadline, leaf_private=True)
            held.append(current)
            require(set(os.listdir(current.fd)) == {parts[index+1]}, 'destination-extra')
        for relative, size, digest in FILES:
            directory = current if relative == ARCHIVE else epoch
            hash_leaf(directory.fd, Path(relative).name, size, digest, deadline, 0o400)
        for directory in held:
            directory.check()
        parent.check()
    finally:
        failed = False
        for directory in reversed(held + [parent]):
            try:
                directory.close()
            except BaseException:
                failed = True
        require(not failed, 'destination-observer-release')

def cleanup_unit(token, pin, invocation, peer, cgroup, deadline, *, work_deadline, source):
    """Only a captured fresh named unit may be signalled; disconnect is no proof."""
    require(peer == session_peer(deadline), 'local-manager-peer-changed')
    actual = show(token, deadline,cleanup_deadline=deadline)
    require(actual['Id'] == unit_name(token) and actual['LoadState'] == 'loaded'
            and actual['InvocationID'] == invocation and actual['Transient'] == 'yes',
            'owned-receiver-unit-lost')
    if actual['MainPID'] != '0':
        require(receiver_process(int(actual['MainPID']), token, work_deadline, source, deadline) == pin,
                'owned-receiver-process-changed')
    bounded([SYSTEMCTL, '--user', 'stop', unit_name(token)], deadline, cleanup_deadline=deadline)
    final = show(token, deadline,missing=True,cleanup_deadline=deadline)
    require(cgroup is not None, 'captured-receiver-cgroup-required')
    events = os.pread(cgroup.events, 4097, 0)
    procs = os.pread(cgroup.procs, 4097, 0)
    require(len(events) <= 4096 and dict(row.split(' ', 1) for row in events.decode('ascii').splitlines())
            .get('populated') == '0' and procs.strip() == b'', 'owned-receiver-descendants-not-empty')
    # v260 may collect the stopped transient unit immediately. This is accepted
    # only AFTER exact captured-unit stop, with independent held kernel/PID proof.
    require(final['Id'] == unit_name(token) and final['MainPID'] == '0'
            and final['ControlGroup'] == '' and
            (final['LoadState'] == 'loaded' and final['InvocationID'] == invocation
             and final['Transient'] == 'yes' and final['ActiveState'] in ('inactive', 'failed')
             or final['LoadState'] == 'not-found' and final['ActiveState'] == 'inactive'
             and final['SubState'] == 'dead' and final['InvocationID'] == ''),
            'owned-receiver-unit-not-empty')
    try:
        process(pin[0])
    except FileNotFoundError:
        pass
    else:
        raise ValueError('owned-receiver-pid-not-gone')
    require(peer == session_peer(deadline), 'local-manager-peer-changed')
    return True

def coordinator(token, remote_timestamp, deadline, source, tool_pins):
    """Called by exact OS bootstrap only after authenticated OS+NAR closure checks."""
    import fcntl
    unit_name(token)
    validate_remote_clock(remote_timestamp, deadline)
    parent, preflight, cgroup, runner, pin, peer = None, None, None, None, None, None
    success, cleanup, failure, invocation = False, False, None, None
    try:
        require(type(tool_pins) is dict and set(tool_pins) == set(TOOLS), 'declared-receiver-tools')
        # Exact executables are qualified by the sender's registered closure
        # comparison and this independent physical byte read before any launch.
        for path in TOOLS:
            expected = tool_pins[path]
            require(type(expected) is dict and set(expected) == {'sha256', 'bytes'}
                    and type(expected['bytes']) is int and 0 < expected['bytes'] <= 64*1024**2
                    and type(expected['sha256']) is str and re.fullmatch('[a-f0-9]{64}', expected['sha256']),
                    'declared-receiver-tool-pin')
            directory = Directory(str(Path(path).parent), deadline, immutable_tool=True)
            try:
                fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory.fd)
                try:
                    before = os.fstat(fd)
                    require(stat.S_ISREG(before.st_mode) and before.st_uid == 0
                            and before.st_nlink >= 1 and not before.st_mode & 0o222
                            and before.st_mode & 0o111 and before.st_size == expected['bytes'],
                            'declared-receiver-tool-custody')
                    raw, count = hashlib.sha256(), 0
                    while True:
                        tick(deadline)
                        data = os.read(fd, FRAME)
                        if not data:
                            break
                        count += len(data)
                        raw.update(data)
                    require(count == expected['bytes'] and raw.hexdigest() == expected['sha256']
                            and file_identity(before) == file_identity(os.fstat(fd))
                            == file_identity(os.stat(Path(path).name, dir_fd=directory.fd,
                                                     follow_symlinks=False)), 'declared-receiver-tool-bytes')
                    directory.check()
                finally:
                    os.close(fd)
            finally:
                directory.close()
        parent = Directory(PARENT, deadline)
        fcntl.flock(parent.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        absent(parent)
        peer = session_peer(deadline)
        disposition = default_disposition(deadline)
        before = show(token, deadline, missing=True)
        require(before['LoadState'] == 'not-found' and before['MainPID'] == '0'
                and before['ControlGroup'] == '' and before['ActiveState'] == 'inactive'
                and before['SubState'] == 'dead', 'fresh-receiver-unit-required')
        command, runtime_us = receiver_command(token, deadline, source)
        # Direct inherited SSH pipes: payload streaming and hashing occurs only
        # in the resource-bounded receiver, not an unbounded OS relay process.
        runner = subprocess.Popen(command, stdin=0, stdout=1, stderr=subprocess.PIPE,
                                  env=manager_environment(), start_new_session=True)
        os.set_blocking(runner.stderr.fileno(), False)
        while True:
            tick(deadline)
            actual = show(token, deadline)
            if actual['ActiveState'] == 'active':
                break
            require(actual['ActiveState'] in ('inactive', 'activating'), 'receiver-start-failed')
            with selectors.DefaultSelector() as selector:
                selector.register(runner.stderr, selectors.EVENT_READ)
                if selector.select(min(0.05, tick(deadline))):
                    require(not os.read(runner.stderr.fileno(), 4096), 'receiver-start-diagnostic')
        require(actual['Id'] == unit_name(token) and actual['Transient'] == 'yes'
                and re.fullmatch('[1-9][0-9]*', actual['MainPID'])
                and re.fullmatch('[a-f0-9]{32}', actual['InvocationID'])
                and actual['InvocationID'] != '0'*32, 'created-unit-identity')
        pin = receiver_process(int(actual['MainPID']), token, deadline, source, deadline)
        invocation = actual['InvocationID']
        pid, path = verify_unit(actual, token, runtime_us)
        cgroup = cgroup_pin(path, pid, deadline)
        parent.check()
        absent(parent)
        require(peer == session_peer(deadline), 'local-manager-peer-changed')
        require(default_disposition(deadline)==disposition,'default-disposition-changed')
        emit(1, {'scope': SCOPE, 'phase': 'go-ready', 'token': token,
                 'pid': pid, 'start': pin[1], 'uid': pin[2],
                 'caps_verified': True, 'physical_parent_verified': True}, deadline)
        # Root validates the exact gate and sends GO directly to the unit's
        # inherited pipe. The observer never reads/forwards payload frames.
        while True:
            tick(deadline)
            actual = show(token, deadline)
            if actual['MainPID'] == '0':
                require(actual['ActiveState'] == 'active' and actual['SubState'] == 'exited'
                        and actual['Result'] == 'success' and actual['ExecMainStatus'] == '0'
                        and actual['InvocationID'] == invocation, 'receiver-workload-failed')
                break
            require(actual['InvocationID'] == invocation and
                    receiver_process(int(actual['MainPID']), token, deadline, source, deadline) == pin
                    and peer == session_peer(deadline), 'running-receiver-identity-changed')
            cgroup.check()
            require(default_disposition(deadline)==disposition,'default-disposition-changed')
            with selectors.DefaultSelector() as selector:
                selector.register(runner.stderr, selectors.EVENT_READ)
                if selector.select(min(0.05, tick(deadline))):
                    require(not os.read(runner.stderr.fileno(), 4096), 'receiver-diagnostic-refused')
        destination_readback(deadline)
        parent.check()
        success = True
    except BaseException as error:
        failure = error
    finally:
        # Use the SAME translated original deadline, only its reserved tail.
        cleanup_deadline = deadline + RESERVE_NS
        if pin is not None:
            try:
                cleanup = cleanup_unit(token, pin, invocation, peer, cgroup, cleanup_deadline,
                                       work_deadline=deadline, source=source)
            except BaseException:
                success = False
        elif runner is not None:
            # No qualified identity means no signalling guessed services.
            success = False
        if runner is not None:
            for stream in (runner.stderr,):
                try:
                    stream.close()
                except BaseException:
                    success = False
            try:
                if runner.poll() is None:
                    runner.kill()
                runner.wait(timeout=tick(cleanup_deadline))
            except BaseException:
                success = False
        if cgroup is not None:
            for fd in (getattr(cgroup, 'events', None), getattr(cgroup, 'procs', None)):
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException:
                        success = False
        for held in (cgroup, preflight, parent):
            if held is not None:
                try:
                    held.close()
                except BaseException:
                    success = False
    require(failure is None and success and cleanup, 'receiver-staging-refused')
    destination_readback(deadline + RESERVE_NS)
    require(default_disposition(deadline + RESERVE_NS, cleanup_deadline=deadline + RESERVE_NS)==disposition,'default-disposition-changed')
    emit(1, {'scope': SCOPE, 'phase': 'complete', 'token': token,
             'files': 2, 'bytes': sum(row[1] for row in FILES),
             'receiver_cleanup_verified': True, 'destination_rehashed': True,
             'installation': False, 'ready': False}, deadline + RESERVE_NS)

DEFAULT_UNIT = 'ai.xoxd.omux.service'
DEFAULT_SHOW=('Id','LoadState','ActiveState','SubState','MainPID','ControlGroup')

def default_disposition(deadline, *, cleanup_deadline=None):
    """Only this named default unit; no ownership/Ready/global absence claim."""
    status,data=bounded([SYSTEMCTL,'--user','show',DEFAULT_UNIT,
              '--property='+','.join(DEFAULT_SHOW)],deadline,accept=(0,4),return_status=True,
              cleanup_deadline=cleanup_deadline)
    value=properties(data,DEFAULT_SHOW)
    require(status==0 or status==4 and value['LoadState']=='not-found','default-unit-error-status')
    require(value['Id']==DEFAULT_UNIT and value['LoadState'] in ('loaded','not-found')
            and value['ActiveState']=='inactive' and value['SubState']=='dead'
            and value['MainPID']=='0' and value['ControlGroup']=='',
            'default-named-unit-not-inactive')
    uid=str(os.getuid())
    path=Path('/sys/fs/cgroup/user.slice')/('user-'+uid+'.slice')/('user@'+uid+'.service')/'app.slice'/DEFAULT_UNIT
    # Exact fixed cgroup ancestry; tolerate only genuine ENOENT, not an alias,
    # access refusal, process discovery or enumeration of other service roles.
    held=None
    for candidate in (path.parent,path.parent.parent):
        try:
            held=Directory(candidate,deadline)
            break
        except FileNotFoundError:
            if candidate==path.parent.parent:
                raise
    try:
        missing=path.parent.name if held.path==path.parent.parent else path.name
        try:
            info=os.stat(missing,dir_fd=held.fd,follow_symlinks=False)
        except FileNotFoundError:
            held.check()
            return {'default_named_unit_inactive_or_missing':True,'cgroup_absent':True}
        require(stat.S_ISDIR(info.st_mode),'default-cgroup-alias')
        require(held.path==path.parent,'default-app-slice-appeared')
        group=Directory(path,deadline)
        try:
            values={}
            for name in ('cgroup.procs','cgroup.events'):
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=group.fd)
                try:
                    data=os.read(fd,4097)
                    require(len(data)<=4096 and os.read(fd,1)==b'','default-cgroup-bound')
                    values[name]=data.decode('ascii').strip()
                finally:
                    os.close(fd)
            events={}
            for row in values['cgroup.events'].splitlines():
                key,item=row.split(' ',1)
                require(key not in events,'default-cgroup-duplicate')
                events[key]=item
            require(not values['cgroup.procs'] and events.get('populated')=='0','default-cgroup-populated')
            group.check()
            return {'default_named_unit_inactive_or_missing':True,'cgroup_absent':False}
        finally:
            group.close()
    finally:
        held.close()
