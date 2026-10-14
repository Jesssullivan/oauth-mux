"""Owned parent of the one installed console qualifier, outside its slice.

Only its own blocked child is enrolled. The original terminal, audit session,
compositor, resident service and guardian cgroup are never moved or signalled.
This control-process boundary does not cap unrelated host/session processes.
"""
import ctypes
import hashlib
import math
import os
from pathlib import Path
import pwd
import re
import select
import signal
import stat
import subprocess
import time
import uuid

import guard_native_seed_plan_reserved as kernel
import guard_resident_observation as resident
import guard_yoga_profile as yoga
import guard_yoga_toolbar_reserved as toolbar
import yoga_display_binding as display
import yoga_local_console_scope as console
import yoga_session_qualification as qualification

PREPARE_NS = 15 * 10**9
CLEANUP_NS = 30 * 10**9


def require(condition):
    if condition is not True:
        raise ValueError('local-parent-envelope-refused')


class UnsettledChild(ValueError):
    """Live API refusal, never a claim of custody after the caller exits."""
    def __init__(self, projection, custody):
        super().__init__('local-parent-owned-child-unsettled')
        self.projection, self.custody = projection, custody


class UnsettledCustody:
    """Keep original wait authority and held resources in the live parent.

    There is no detached reaper, renewed clock, module-global owner or daemon.
    The current prepare CLI cannot transfer this object across process exit.
    """
    def __init__(self, child, pidfd, image, parent, resources, entry, deadline, cutoff):
        self.child, self.pidfd, self.image, self.parent = child, pidfd, image, parent
        self.resources, self.entry, self.deadline, self.cutoff = resources, entry, deadline, cutoff
        self.reaped, self.status, self.closed = False, None, False

    def poll_terminal(self):
        # One nonblocking observation by the original parent only. This does
        # not execute tools, reset a deadline, signal a child or qualify units.
        require(not self.closed and os.getpid() == self.parent.pid
            and kernel.process(self.parent.pid) == self.parent.image
            and resident.file_identity(os.fstat(self.parent.exe_fd)) == self.parent.exe_identity
            == resident.file_identity(os.stat('/proc/self/exe')))
        fd = os.open('/proc/self/cgroup', os.O_RDONLY | os.O_CLOEXEC)
        try:
            require(os.read(fd, 4097) == self.parent.group)
        finally:
            os.close(fd)
        console.recheck_terminal(self.parent.terminal_descriptor, self.parent.terminal)
        if not self.reaped:
            require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL)
            pid, status = os.waitpid(self.child, os.WNOHANG)
            require(pid in (0, self.child))
            if pid == self.child:
                self.reaped, self.status = True, status
            elif self.image is not None:
                require(kernel.process(self.child) == self.image)
        return self.reaped

    def close_reaped(self):
        require(self.reaped and not self.closed)
        # Closing these observations does not assert descendant/unit cleanup.
        for value in self.resources:
            if value is not None: value.close()
        if self.pidfd is not None:
            os.close(self.pidfd); self.pidfd = None
        self.closed = True


class Parent:
    def __init__(self, entry, deadline, terminal_descriptor):
        self.entry, self.deadline, self.terminal_descriptor = entry, deadline, terminal_descriptor
        kernel.remaining(entry, deadline)
        self.pid = os.getpid()
        self.image = kernel.process(self.pid)
        self.group = yoga.file_bytes('/proc/self/cgroup', 4096, deadline)
        self.terminal = console.terminal_identity(terminal_descriptor)
        self.pidfd = self.exe_fd = None
        try:
            self.pidfd = os.pidfd_open(self.pid, 0)
            self.exe_fd = os.open('/proc/self/exe', os.O_RDONLY | os.O_CLOEXEC)
            info = os.fstat(self.exe_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o222)
            self.exe_identity = resident.file_identity(info)
        except BaseException:
            self.close(); raise

    def bind_image(self, declared_python):
        # Runtime/NAR qualification precedes this call. The exact selected
        # Python image must be the already running guardian, not just a name.
        require(resident.file_identity(os.stat(declared_python)) == self.exe_identity
            == resident.file_identity(os.fstat(self.exe_fd)))

    def child_image(self, pid):
        fd = os.open('/proc/' + str(pid) + '/exe', os.O_RDONLY | os.O_CLOEXEC)
        try:
            require(resident.file_identity(os.fstat(fd)) == self.exe_identity
                == resident.file_identity(os.stat('/proc/' + str(pid) + '/exe')))
        finally:
            os.close(fd)

    def observe(self, *, cleanup=False):
        kernel.remaining(self.entry, self.deadline, cleanup=cleanup)
        require(os.getpid() == self.pid and kernel.process(self.pid) == self.image
            and yoga.file_bytes('/proc/self/cgroup', 4096, self.deadline) == self.group
            and resident.file_identity(os.fstat(self.exe_fd)) == self.exe_identity
            == resident.file_identity(os.stat('/proc/self/exe'))
            and not select.select([self.pidfd], [], [], 0)[0])
        console.recheck_terminal(self.terminal_descriptor, self.terminal)

    def close(self):
        for name in ('exe_fd', 'pidfd'):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd); setattr(self, name, None)


class Manager(console.Manager):
    """Same registered systemd interface, only this fresh pair of units."""
    def __init__(self, tools, token, entry, deadline, *, slice_unit=False):
        require(type(token) is str and re.fullmatch('[a-f0-9]{32}', token) is not None)
        require(type(slice_unit) is bool)
        self.tools, self.entry, self.deadline = tools, entry, deadline
        self.project_slice = 'omuxyogaconsole' + token + '.slice'
        self.unit = self.project_slice if slice_unit else 'omux-yoga-console-envelope-' + token + '.scope'
        self.slice_unit = slice_unit
        self.cutoff = min(deadline - kernel.RESERVE_NS, time.monotonic_ns() + PREPARE_NS)
        self.KEYS = tuple(key for key in console.Manager.KEYS if key != 'RuntimeMaxUSec') if slice_unit else console.Manager.KEYS

    def phase(self, *, cleanup=False):
        left = min(kernel.remaining(self.entry, self.deadline, cleanup=cleanup),
                   (self.cutoff - time.monotonic_ns()) / 10**9)
        require(left > 0)
        return min(15, left)

    def watching(self):
        self.cutoff = self.deadline - kernel.RESERVE_NS

    def cleaning(self, cutoff):
        require(type(cutoff) is int and cutoff <= self.deadline)
        self.cutoff = cutoff

    def call(self, arguments, *, cleanup=False, absent=False):
        result = subprocess.run([self.tools['systemctl'], '--system', *arguments],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=self.phase(cleanup=cleanup), check=False)
        self.phase(cleanup=cleanup)
        require(result.returncode in ((0, 4) if absent else (0,)) and len(result.stdout) <= 8192)
        return result.stdout

    def show(self, *, cleanup=False):
        raw = self.call(['show', '--property=' + ','.join(self.KEYS), self.unit], cleanup=cleanup, absent=True)
        pairs = [row.split('=', 1) for row in raw.decode('ascii').splitlines()]
        require(all(len(row) == 2 for row in pairs) and len(pairs) == len({row[0] for row in pairs}))
        facts = dict(pairs)
        require(set(facts) == set(self.KEYS) and facts['Id'] == self.unit)
        return facts

    def absent(self):
        facts = self.show()
        require(facts['LoadState'] == 'not-found' and facts['ActiveState'] == 'inactive'
            and not facts['InvocationID'] and not facts['ControlGroup'])

    def create(self, pid=None, seconds=None):
        if not self.slice_unit:
            require(type(pid) is int and pid > 1 and type(seconds) is int and 1 <= seconds <= 1170)
        else:
            require(pid is None and seconds is None)
        root = Path(*Path(self.tools['systemctl']).parts[:4])
        library = root / 'lib/libsystemd.so.0'
        api = ctypes.CDLL(str(library))
        api.sd_bus_open_system.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        api.sd_bus_set_method_call_timeout.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        api.sd_bus_unref.argtypes = [ctypes.c_void_p]
        api.sd_bus_message_unref.argtypes = [ctypes.c_void_p]
        api.sd_bus_call_method.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p]
        properties = [b'MemoryMax', b't', ctypes.c_uint64(console.MEMORY),
            b'MemorySwapMax', b't', ctypes.c_uint64(0),
            b'MemoryOOMGroup', b'b', ctypes.c_int(1),
            b'TasksMax', b't', ctypes.c_uint64(console.TASKS),
            b'CPUQuotaPerSecUSec', b't', ctypes.c_uint64(console.CPU * 10000),
            b'Description', b's', b'Omux owned installed console envelope']
        count = 6
        if not self.slice_unit:
            properties += [b'PIDs', b'au', ctypes.c_int(1), ctypes.c_uint32(pid),
                b'RuntimeMaxUSec', b't', ctypes.c_uint64(seconds * 10**6),
                b'Slice', b's', self.project_slice.encode()]
            count = 9
        bus, reply = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            require(api.sd_bus_open_system(ctypes.byref(bus)) >= 0)
            require(api.sd_bus_set_method_call_timeout(bus, ctypes.c_uint64(int(self.phase() * 10**6))) >= 0)
            require(api.sd_bus_call_method(bus, b'org.freedesktop.systemd1', b'/org/freedesktop/systemd1',
                b'org.freedesktop.systemd1.Manager', b'StartTransientUnit', None, ctypes.byref(reply),
                b'ssa(sv)a(sa(sv))', self.unit.encode(), b'fail', ctypes.c_int(count),
                *properties, ctypes.c_int(0)) >= 0)
            self.phase()
        finally:
            if reply.value: api.sd_bus_message_unref(reply)
            if bus.value: api.sd_bus_unref(bus)

    def stop(self, invocation):
        facts = self.show(cleanup=True)
        require(facts['LoadState'] == 'loaded' and facts['InvocationID'] == invocation)
        self.call(['stop', self.unit], cleanup=True)


class Slice:
    """Frozen fresh aggregate anchor; stop is legal only after child settlement."""
    def __init__(self, manager):
        self.manager, self.chain, self.bounds = manager, [], None
        require(manager.slice_unit)
        try:
            facts = manager.show()
            self.invocation, self.group = facts['InvocationID'], facts['ControlGroup']
            require(re.fullmatch('[a-f0-9]{32}', self.invocation) is not None
                and self.group == '/' + manager.unit)
            self.chain = kernel.open_chain(Path('/sys/fs/cgroup' + self.group))
            self.observe()
        except BaseException:
            self.close(); raise

    def read(self, name):
        return console.Scope.read(self, name)

    def anchored(self, *, allow_absent=False):
        return console.Scope.anchored(self, allow_absent=allow_absent)

    def observe(self, *, cleanup=False):
        self.manager.phase(cleanup=cleanup)
        require(self.anchored())
        facts = self.manager.show(cleanup=cleanup)
        require(facts['LoadState'] == 'loaded' and facts['ActiveState'] == 'active'
            and facts['InvocationID'] == self.invocation and facts['ControlGroup'] == self.group
            and facts['MemoryMax'] == str(console.MEMORY) and facts['MemorySwapMax'] == '0'
            and facts['MemoryOOMGroup'] == 'yes' and facts['TasksMax'] == str(console.TASKS)
            and facts['CPUQuotaPerSecUSec'] == '1.9s')
        values = console.cap_values({name: self.read(name) for name in
            ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max', 'memory.oom.group')})
        require(self.bounds is None or values == self.bounds)
        self.bounds = values
        require(self.anchored())

    def settle(self):
        self.observe(cleanup=True)
        require(not self.read('cgroup.procs') and 'populated 0' in self.read('cgroup.events').splitlines())
        # Parent is outside this slice. Its original cgroup is never stopped.
        self.manager.stop(self.invocation)
        for _ in range(2):
            self.manager.phase(cleanup=True)
            exists = self.anchored(allow_absent=True)
            facts = self.manager.show(cleanup=True)
            if exists:
                require(facts['LoadState'] == 'loaded' and facts['InvocationID'] == self.invocation
                    and facts['ControlGroup'] == self.group and facts['ActiveState'] in ('inactive', 'failed')
                    and not self.read('cgroup.procs') and 'populated 0' in self.read('cgroup.events').splitlines())
                require(console.cap_values({name: self.read(name) for name in
                    ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max', 'memory.oom.group')}) == self.bounds)
            else:
                require(facts['LoadState'] == 'not-found' and facts['ActiveState'] == 'inactive'
                    and not facts['InvocationID'] and not facts['ControlGroup'])
        return True

    def close(self):
        chain, self.chain = self.chain, []
        resident.close_owned_resources([row[1] for row in chain])


def release_go(channel, child, pidfd, image, parent, scope, aggregate, reservation, verify):
    parent.observe()
    require(kernel.process(child) == image and image[2] == parent.image[2]
        and not select.select([pidfd], [], [], 0)[0])
    parent.child_image(child)
    verify()
    parent.child_image(child)
    aggregate.observe(); reservation.observe(); scope.observe()
    parent.observe()
    require(os.write(channel, b'G') == 1)


def cleanup_remaining(entry, deadline, cutoff):
    left = min(kernel.remaining(entry, deadline, cleanup=True),
               (cutoff - time.monotonic_ns()) / 10**9)
    require(left > 0)
    return left


def cooperate(child, pidfd, scope, parent, entry, deadline, cutoff):
    """Let the console owner settle its sibling scope before scoped fallback."""
    if select.select([pidfd], [], [], 0)[0]:
        return
    parent.observe(cleanup=True)
    parent.child_image(child)
    require(kernel.process(child) == scope.initial and scope.anchored())
    facts = scope.manager.show(cleanup=True)
    require(facts['LoadState'] == 'loaded' and facts['InvocationID'] == scope.invocation
        and facts['ControlGroup'] == scope.group and facts['MemoryMax'] == str(console.MEMORY)
        and facts['MemorySwapMax'] == '0' and facts['MemoryOOMGroup'] == 'yes'
        and facts['TasksMax'] == str(console.TASKS) and facts['CPUQuotaPerSecUSec'] == '1.9s')
    toolbar.verify_runtime(facts['RuntimeMaxUSec'], scope.seconds)
    require(console.cap_values({name:scope.read(name) for name in
        ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group')}) == scope.bounds
        and str(child) in scope.read('cgroup.procs').splitlines() and scope.anchored())
    left = min(15, cleanup_remaining(entry, deadline, cutoff))
    # Only the frozen original fork/pidfd receives this signal. The user's
    # terminal process group and original session never receive a signal here.
    signal.pidfd_send_signal(pidfd, signal.SIGINT)
    select.select([pidfd], [], [], left)


def settle_ready(child, pidfd, scope, waited, cleaned, mark_reaped):
    """Qualify normal disappearance before any ownership-checked stop."""
    if not waited and pidfd is not None and select.select([pidfd], [], [], 0)[0]:
        pid, status = os.waitpid(child, os.WNOHANG)
        require(pid == child)
        mark_reaped(); waited = True
        if scope is not None:
            scope.terminal(status)
            try:
                cleaned = scope.cleanup() is True
            except BaseException:
                # The caller uses the common scoped ownership/cleanup fallback.
                cleaned = False
    return waited, cleaned


class OwnedOperation:
    """Private coordinator record; exact recorded scopes, never control authority.

    Created unresolved before any unit/fork. Updates require the held inode and
    original clock; timeout leaves the last unresolved record in place.
    """
    def __init__(self, output, entry, deadline, parent, aggregate_unit, selection_sha256, graph_sha256):
        import json
        import yoga_display_binding as binding
        self.entry, self.deadline, self.parent = entry, deadline, parent
        require(type(selection_sha256) is str and type(graph_sha256) is str
            and re.fullmatch("[a-f0-9]{64}", selection_sha256) is not None
            and re.fullmatch("[a-f0-9]{64}", graph_sha256) is not None)
        self.selection_sha256, self.graph_sha256 = selection_sha256, graph_sha256
        self.cleanup_cutoff = None
        self.published_state = None
        self.directory = self.fd = None
        self.operation_id = uuid.uuid4().hex
        self.name = '.omux-console-operation-' + self.operation_id + '.json'
        self.path = Path(output).parent / self.name
        self.row = {'schemaVersion': 1, 'scope': 'yoga-original-guardian-operation-v1',
            'operationId': self.operation_id, 'state': 'unresolved',
            'originalEntryMonotonicNs': entry, 'deadlineMonotonicNs': deadline,
            'guardianPid': parent.pid, 'guardianImage': list(parent.image),
            'guardianCgroupSha256': hashlib.sha256(parent.group).hexdigest(),
            'selectionSha256': selection_sha256, 'sourceGraphSha256': graph_sha256,
            'terminalIdentity': list(parent.terminal), 'scopePolicyVersion': 'direct-manager-v1',
            'aggregateUnit': aggregate_unit, 'aggregate': None,
            'workerUnit': None, 'worker': None, 'child': None, 'goState': 'not-requested',
            'originalChildReaped': False, 'workerCleanupEmpty': False,
            'aggregateCleanupEmpty': False, 'executionAuthority': False}
        try:
            kernel.remaining(entry, deadline)
            self.directory = binding.parent_descriptor(str(self.path.parent), os.getuid())
            self.directory_identity = resident.file_identity(os.fstat(self.directory))[:5]
            self.fd = os.open(self.name, os.O_RDWR | os.O_CREAT | os.O_EXCL |
                os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=self.directory)
            self.identity = self.file_identity(os.fstat(self.fd))
            self.write()
        except BaseException:
            self.close(); raise

    @staticmethod
    def file_identity(info):
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1)
        return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink

    def recheck(self):
        require(self.fd is not None and self.directory is not None
            and resident.file_identity(os.fstat(self.directory))[:5] == self.directory_identity
            and self.file_identity(os.fstat(self.fd)) == self.identity
            == self.file_identity(os.stat(self.name, dir_fd=self.directory, follow_symlinks=False)))
        import yoga_display_binding as binding
        named = binding.parent_descriptor(str(self.path.parent), os.getuid())
        try:
            require(resident.file_identity(os.fstat(named))[:5] == self.directory_identity)
        finally:
            os.close(named)

    def phase(self):
        left = kernel.remaining(self.entry, self.deadline, cleanup=True)
        if self.cleanup_cutoff is not None:
            require(type(self.cleanup_cutoff) is int and self.cleanup_cutoff <= self.deadline)
            left = min(left, (self.cleanup_cutoff - time.monotonic_ns()) / 10**9)
        require(left > 0)
        return left

    def write(self):
        import json
        self.phase()
        self.recheck()
        raw = json.dumps(self.row, sort_keys=True, separators=(',', ':')).encode()
        require(0 < len(raw) <= 16384)
        offset = 0
        while offset < len(raw):
            self.phase()
            amount = os.pwrite(self.fd, raw[offset:], offset)
            require(amount > 0); offset += amount
        self.phase(); os.ftruncate(self.fd, len(raw)); self.phase()
        os.fsync(self.fd); self.phase()
        os.fsync(self.directory); self.phase()
        self.recheck()
        self.phase()
        self.published_state = self.row['state']

    @staticmethod
    def anchor(value):
        return {'unit': value.manager.unit, 'invocationId': value.invocation,
            'controlGroup': value.group, 'kernelBounds': dict(value.bounds),
            'cgroupIdentity': list(value.chain[-1][2])}

    def bind_aggregate(self, aggregate):
        aggregate.observe()
        self.row['aggregate'] = self.anchor(aggregate); self.write()

    def before_fork(self, manager):
        require(self.row['workerUnit'] is None and manager.project_slice == self.row['aggregateUnit'])
        self.row['workerUnit'] = manager.unit; self.write()

    def after_fork(self, child):
        require(type(child) is int and child > 1 and self.row['child'] is None)
        self.row['child'] = {'pid': child, 'originalParent': self.parent.pid,
            'processIdentity': list(kernel.process(child))}
        self.write()

    def before_go(self, scope):
        require(scope.manager.unit == self.row['workerUnit'])
        scope.observe()
        self.row['worker'] = dict(self.anchor(scope), pid=scope.pid,
            processIdentity=list(scope.initial), runtimeSeconds=scope.seconds,
            managerPolicy=scope.manager.policy(scope.manager.show()))
        self.write()

    def go(self):
        self.row['goState'] = 'requested'; self.write()

    def released(self):
        self.row['goState'] = 'released'; self.write()

    def terminal(self, reaped, worker_empty, aggregate_empty):
        require(all(type(x) is bool for x in (reaped, worker_empty, aggregate_empty)))
        self.row.update(originalChildReaped=reaped, workerCleanupEmpty=worker_empty,
            aggregateCleanupEmpty=aggregate_empty)
        self.row['state'] = 'empty' if reaped and worker_empty and aggregate_empty else 'unresolved'
        self.write()

    def close(self):
        for name in ('fd', 'directory'):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor); setattr(self, name, None)


def read_operation(output_parent, operation_id, deadline):
    """Coordinator readback of one selected record, never permission to stop."""
    import json
    require(type(operation_id) is str and re.fullmatch('[a-f0-9]{32}', operation_id) is not None)
    name = '.omux-console-operation-' + operation_id + '.json'
    directory = display.parent_descriptor(str(output_parent), os.getuid())
    fd = None
    try:
        require(time.monotonic_ns() < deadline)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
        OwnedOperation.file_identity(os.fstat(fd))
        identity = resident.file_identity(os.fstat(fd))
        require(os.fstat(fd).st_size <= 16384)
        raw = bytearray()
        while True:
            require(time.monotonic_ns() < deadline)
            piece = os.read(fd, 4096)
            if not piece: break
            raw.extend(piece); require(len(raw) <= 16384)
        require(identity == resident.file_identity(os.fstat(fd))
            == resident.file_identity(os.stat(name, dir_fd=directory, follow_symlinks=False)))
        def unique(pairs):
            result = {}
            for key, value in pairs:
                require(key not in result); result[key] = value
            return result
        row = json.loads(raw, object_pairs_hook=unique)
        require(type(row) is dict and set(row) == {'schemaVersion', 'scope', 'operationId', 'state',
            'originalEntryMonotonicNs', 'deadlineMonotonicNs', 'guardianPid', 'guardianImage',
            'guardianCgroupSha256', 'selectionSha256', 'sourceGraphSha256', 'terminalIdentity', 'scopePolicyVersion',
            'aggregateUnit', 'aggregate', 'workerUnit', 'worker', 'child', 'goState',
            'originalChildReaped', 'workerCleanupEmpty', 'aggregateCleanupEmpty', 'executionAuthority'}
            and type(row['schemaVersion']) is int and row['schemaVersion'] == 1 and row['scope'] == 'yoga-original-guardian-operation-v1'
            and row['operationId'] == operation_id and row['state'] in ('empty', 'unresolved')
            and row['executionAuthority'] is False and row['goState'] in ('not-requested', 'requested', 'released'))
        require(type(row['originalEntryMonotonicNs']) is int and type(row['deadlineMonotonicNs']) is int
            and row['deadlineMonotonicNs'] - row['originalEntryMonotonicNs'] == 1200 * 10**9)
        require(all(type(row[field]) is bool for field in ('originalChildReaped', 'workerCleanupEmpty', 'aggregateCleanupEmpty')))
        if row['state'] == 'empty':
            require(row['originalChildReaped'] and row['workerCleanupEmpty'] and row['aggregateCleanupEmpty'])
        return {'record': row, 'sha256': hashlib.sha256(raw).hexdigest(), 'executionAuthority': False,
            'cleanupControlAuthority': False, 'completionQualified': False}
    finally:
        if fd is not None: os.close(fd)
        os.close(directory)


def run(selection_path, digest, qualification_path, entry, deadline, *, terminal_descriptor=0):
    """Original guardian directly owns the only fixed qualification worker."""
    arguments = ['run', console.LABEL, '--selection', selection_path, '--selection-sha256', digest,
        '--output', qualification_path, '--deadline-monotonic-ns', str(deadline)]
    console.request(arguments)
    uid, home = os.getuid(), Path(pwd.getpwuid(os.getuid()).pw_dir)
    selected = toolbar.selection(qualification.read_selection(selection_path, digest, deadline), deadline, uid, home)
    require(toolbar.clock(selected, deadline) == (entry, deadline))
    parent = Parent(entry, deadline, terminal_descriptor)
    capture = endpoint = reservation = aggregate = operation = None
    worker = None
    failures = []
    cleanup_cutoff = None
    worker_reaped = worker_empty = aggregate_empty = False
    try:
        import guard_yoga_installed_workspace as installed
        source = Path(selected['sourceRoot'])
        require(Path(__file__).resolve() == source / 'tools/yoga_local_parent_envelope.py')
        capture = installed.Capture(source, selected['installedWorkspace'], deadline, yoga.file_bytes)
        witness, endpoint = display.capture_pinned(selected['sourceSocket'],
            selected['stateRoot'] + '/' + selected['proofId'] + '/wayland.sock',
            selected['stateRoot'] + '/' + selected['proofId'], uid, deadline)
        require(qualification.graph_capture(source, deadline) == selected['sourceGraphSha256'])
        capture.qualify(selected, selected['sourceGraphSha256'])
        qualification.identity_capture(selected, deadline, uid, terminal_descriptor)
        endpoint.check(witness); parent.observe()
        yoga.runtime_qualification(selected, deadline)
        parent.bind_image(selected['controllerTools']['python'])
        reservation = kernel.Witness(entry, deadline)
        manager = Manager(selected['controllerTools'], uuid.uuid4().hex, entry, deadline, slice_unit=True)
        manager.absent()
        operation = OwnedOperation(qualification_path, entry, deadline, parent, manager.unit,
            digest, selected['sourceGraphSha256'])
        manager.create(); aggregate = Slice(manager)
        operation.bind_aggregate(aggregate)
        manager.watching()
        project = console.DirectProject(parent, aggregate)
        worker = console.run(arguments, terminal_descriptor=terminal_descriptor,
            original_project=project, operation=operation)
        worker_reaped = worker.get('workerPidfdExitReady') is True
        worker_empty = worker.get('ownedCleanupEmpty') is True
    except console.Refusal as error:
        failures.append('worker-refused')
        worker_reaped = error.projection.get('originalChildReaped') is True
        worker_empty = error.projection.get('ownedCleanupEmpty') is True
        # The system manager retains the exact registered worker scope, not a
        # Python exception across exit. The unresolved record predates Go.
        if error.custody is not None:
            custody = error.custody
            for value in custody.resources:
                if value is not None and value is not project:
                    try: value.close()
                    except BaseException: failures.append('release-refused')
            for fd in dict.fromkeys(custody.descriptors):
                if fd is not None:
                    try: os.close(fd)
                    except BaseException: failures.append('release-refused')
    except BaseException:
        failures.append('guardian-refused')
    finally:
        cleanup_cutoff = (operation.cleanup_cutoff if operation is not None and operation.cleanup_cutoff is not None
            else min(deadline, time.monotonic_ns() + CLEANUP_NS))
        if operation is not None: operation.cleanup_cutoff = cleanup_cutoff
        if aggregate is not None:
            aggregate.manager.cleaning(cleanup_cutoff)
            if worker_reaped and worker_empty:
                try: aggregate_empty = aggregate.settle() is True
                except BaseException: failures.append('aggregate-cleanup-refused')
        if operation is not None:
            try: operation.terminal(worker_reaped, worker_empty, aggregate_empty)
            except BaseException: failures.append('operation-update-refused')
        try: parent.observe(cleanup=True)
        except BaseException: failures.append('guardian-identity-refused')
        for value in (operation, aggregate, reservation, endpoint, capture, parent):
            if value is not None:
                try: value.close()
                except BaseException: failures.append('release-refused')
    # Identity readbacks and resource release cannot renew cleanup adoption.
    try: cleanup_remaining(entry, deadline, cleanup_cutoff)
    except BaseException: failures.append('final-cleanup-clock-refused')
    success = not failures and worker is not None and worker.get('exit') == 0 and worker_reaped and worker_empty and aggregate_empty
    return {'scope': 'yoga-original-guardian-console-v1', 'exit': 0 if success else 125,
        'originalChildReaped': worker_reaped, 'workerCleanupEmpty': worker_empty,
        'aggregateCleanupEmpty': aggregate_empty, 'cleanupState': 'empty' if worker_reaped and worker_empty and aggregate_empty else 'unproved',
        'operationId': operation.operation_id if operation is not None else None,
        'cleanupDeadlineMonotonicNs': cleanup_cutoff, 'cleanupCompletionQualified': success,
        'unresolvedOperationRecorded': operation is not None and operation.published_state == 'unresolved',
        'qualificationProduced': success, 'originalEntryMonotonicNs': entry,
        'deadlineMonotonicNs': deadline, 'executionAuthority': False,
        'toolbarConsentProved': False, 'normalSessionMoved': False,
        'waitAuthorityTransferred': False, 'durablePythonCustody': False}
