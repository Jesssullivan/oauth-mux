"""Exact console-born qualification scope; never a generic execution guard.

No service MainPID/ExecMainStatus or synthetic service terminal result is used.
The child is waitable by this console parent, and cannot exec until explicit Go.
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
import yoga_session_qualification as qualification

LABEL = '//tools:yoga_reserved_session_qualification'
MEMORY, TASKS, CPU = 4026531840, 480, 190


class Refusal(ValueError):
    def __init__(self, projection):
        super().__init__('local-console-qualification-refused')
        self.projection = projection


def require(condition):
    if not condition:
        raise ValueError('local-console-qualification-refused')


def terminal_identity(descriptor):
    info = os.fstat(descriptor)
    require(stat.S_ISCHR(info.st_mode) and info.st_uid == os.getuid() and os.isatty(descriptor))
    return resident.stable(info) + (info.st_rdev,)


def recheck_terminal(descriptor, identity):
    require(terminal_identity(descriptor) == identity)


def release_go(channel, scope, reservation):
    reservation.observe()
    scope.observe()
    require(os.write(channel, b'G') == 1)


def settle_reaped(scope, already_cleaned):
    require(type(already_cleaned) is bool)
    if not already_cleaned:
        scope.stop_owned()
        scope.cleanup()
    return True


def terminate_child(child, pidfd, scope, waited, scope_cleaned, entry, deadline, mark_reaped):
    """Reap the original child once, then settle its frozen owned scope."""
    if child is None:
        return scope_cleaned
    if waited:
        return settle_reaped(scope, scope_cleaned) if scope is not None else scope_cleaned
    stopped = False
    if pidfd is None:
        # This owned child is unreaped and has not received Go.
        os.kill(child, signal.SIGKILL)
    elif not select.select([pidfd], [], [], 0)[0]:
        if scope is not None:
            scope.stop_owned()
            stopped = True
        else:
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
    if pidfd is not None:
        require(select.select([pidfd], [], [], min(15, kernel.remaining(entry, deadline, cleanup=True)))[0])
    pid, status = os.waitpid(child, 0)
    require(pid == child)
    mark_reaped()
    if scope is not None:
        scope.terminal(status)
        if stopped:
            scope.cleanup()
            return True
        # Main exit readiness does not establish descendant emptiness.
        return settle_reaped(scope, scope_cleaned)
    return scope_cleaned


def request(arguments):
    require(type(arguments) is list and len(arguments) == 10
        and arguments[:2] == ['run', LABEL]
        and arguments[2::2] == ['--selection', '--selection-sha256', '--output', '--deadline-monotonic-ns'])
    selection, digest, output, raw = arguments[3::2]
    require(type(raw) is str and raw.isascii() and raw.isdecimal() and len(raw) <= 20)
    deadline = int(raw)
    qualification.selectors(selection, output, deadline)
    require(type(digest) is str and yoga.SHA.fullmatch(digest))
    return selection, digest, output, deadline


def cap_values(values):
    require(type(values) is dict and set(values) == {'memory.max', 'memory.swap.max', 'pids.max', 'cpu.max', 'memory.oom.group'})
    require(values['memory.max'] == str(MEMORY) and values['memory.swap.max'] == '0'
        and values['pids.max'] == str(TASKS) and values['memory.oom.group'] == '1')
    rows = values['cpu.max'].split()
    require(len(rows) == 2 and all(row.isascii() and row.isdecimal() for row in rows))
    quota, period = map(int, rows)
    require(period > 0 and quota * 100 == period * CPU)
    return dict(values)


def call(tool, arguments, entry, deadline, *, cleanup=False, absent=False):
    timeout = min(15, kernel.remaining(entry, deadline, cleanup=cleanup))
    result = subprocess.run([tool, *arguments], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    require(result.returncode in ((0,4) if absent else (0,)) and len(result.stdout) <= 8192)
    return result.stdout


class Manager:
    """Purpose-bound system scope queries; no arbitrary unit or properties."""
    KEYS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'InvocationID', 'ControlGroup',
            'MemoryMax', 'MemorySwapMax', 'MemoryOOMGroup', 'TasksMax', 'CPUQuotaPerSecUSec', 'RuntimeMaxUSec')

    def __init__(self, tools, unit, entry, deadline, project_slice):
        require(yoga.coordinator.UUID.fullmatch(unit.removeprefix('omux-yoga-console-').removesuffix('.scope'))
            and unit.startswith('omux-yoga-console-') and unit.endswith('.scope'))
        self.tools, self.unit, self.entry, self.deadline = tools, unit, entry, deadline
        require(type(project_slice) is str and re.fullmatch(r'omuxyogaconsole[0-9a-f]{32}\.slice',project_slice))
        self.project_slice = project_slice

    def show(self, *, cleanup=False):
        raw = call(self.tools['systemctl'], ['--system', 'show', '--property='+','.join(self.KEYS), self.unit],
            self.entry, self.deadline, cleanup=cleanup, absent=True)
        rows = raw.decode('ascii').splitlines()
        pairs = [row.split('=', 1) for row in rows]
        require(all(len(row) == 2 for row in pairs) and len(pairs) == len({row[0] for row in pairs}))
        facts = dict(pairs)
        require(set(facts) == set(self.KEYS) and facts['Id'] == self.unit)
        return facts

    def create(self, pid, seconds):
        """Use the registered systemd library, not an undeclared busctl executable.

        sd_bus_call_method's public typed varargs encode exactly one scope and
        nine fixed properties. Its method-call timeout has the original bound.
        """
        root = Path(*Path(self.tools['systemctl']).parts[:4])
        library = root / 'lib/libsystemd.so.0'
        require(library.is_relative_to(root))
        api = ctypes.CDLL(str(library))
        api.sd_bus_open_system.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        api.sd_bus_set_method_call_timeout.argtypes = [ctypes.c_void_p, ctypes.c_uint64]
        api.sd_bus_unref.argtypes = [ctypes.c_void_p]
        api.sd_bus_message_unref.argtypes = [ctypes.c_void_p]
        # Fixed prefix only; remaining arguments follow the explicit signature.
        api.sd_bus_call_method.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p]
        bus, reply = ctypes.c_void_p(), ctypes.c_void_p()
        try:
            require(api.sd_bus_open_system(ctypes.byref(bus)) >= 0)
            require(api.sd_bus_set_method_call_timeout(bus,
                ctypes.c_uint64(int(min(15, kernel.remaining(self.entry, self.deadline))*10**6))) >= 0)
            require(api.sd_bus_call_method(bus, b'org.freedesktop.systemd1', b'/org/freedesktop/systemd1',
                b'org.freedesktop.systemd1.Manager', b'StartTransientUnit', None, ctypes.byref(reply),
                b'ssa(sv)a(sa(sv))', self.unit.encode(), b'fail', ctypes.c_int(9),
                b'PIDs', b'au', ctypes.c_int(1), ctypes.c_uint32(pid),
                b'MemoryMax', b't', ctypes.c_uint64(MEMORY),
                b'MemorySwapMax', b't', ctypes.c_uint64(0),
                b'MemoryOOMGroup', b'b', ctypes.c_int(1),
                b'TasksMax', b't', ctypes.c_uint64(TASKS),
                b'CPUQuotaPerSecUSec', b't', ctypes.c_uint64(1900000),
                b'RuntimeMaxUSec', b't', ctypes.c_uint64(seconds*10**6),
                b'Slice', b's', self.project_slice.encode(),
                b'Description', b's', b'Omux exact local-console qualification', ctypes.c_int(0)) >= 0)
        finally:
            if reply.value: api.sd_bus_message_unref(reply)
            if bus.value: api.sd_bus_unref(bus)

    def stop(self, invocation):
        facts = self.show(cleanup=True)
        require(facts['LoadState'] == 'loaded' and facts['InvocationID'] == invocation)
        call(self.tools['systemctl'], ['--system', 'stop', self.unit], self.entry, self.deadline, cleanup=True)


class Scope:
    """Frozen scope name/InvocationID, anchored cgroup, own waitable child/pidfd."""
    def __init__(self, manager, pid, pidfd, seconds):
        self.manager, self.pid, self.pidfd, self.seconds = manager, pid, pidfd, seconds
        self.chain, self.exit_status = [], None
        try:
            facts = manager.show()
            require(facts['LoadState'] == 'loaded' and facts['ActiveState'] == 'active'
                and facts['SubState'] == 'running' and len(facts['InvocationID']) == 32
                and all(c in '0123456789abcdef' for c in facts['InvocationID']))
            self.invocation, self.group = facts['InvocationID'], facts['ControlGroup']
            require(self.group == '/'+manager.project_slice+'/'+manager.unit)
            self.chain = kernel.open_chain(Path('/sys/fs/cgroup'+self.group))
            self.initial = kernel.process(pid)
            self.bounds = None
            self.observe()
        except BaseException:
            self.close()
            raise

    def read(self, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                     dir_fd=self.chain[-1][1])
        try:
            require(stat.S_ISREG(os.fstat(fd).st_mode))
            raw = os.read(fd, 8193)
            require(len(raw) <= 8192 and not os.read(fd, 1))
            return raw.decode('ascii').strip()
        finally:
            os.close(fd)

    def anchored(self, *, allow_absent=False):
        for index, (path, fd, identity) in enumerate(self.chain):
            require(resident.stable(os.fstat(fd)) == identity)
            try:
                named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                    dir_fd=self.chain[index-1][1], follow_symlinks=False)
            except FileNotFoundError:
                require(allow_absent and index == len(self.chain)-1)
                return False
            require(resident.stable(named) == identity)
        return True

    def observe(self):
        kernel.remaining(self.manager.entry, self.manager.deadline)
        require(self.anchored())
        facts = self.manager.show()
        require(facts['LoadState'] == 'loaded' and facts['ActiveState'] == 'active'
            and facts['SubState'] == 'running' and facts['InvocationID'] == self.invocation
            and facts['ControlGroup'] == self.group and facts['MemoryMax'] == str(MEMORY)
            and facts['MemorySwapMax'] == '0' and facts['MemoryOOMGroup'] == 'yes' and facts['TasksMax'] == str(TASKS)
            and facts['CPUQuotaPerSecUSec'] == '1.9s')
        toolbar.verify_runtime(facts['RuntimeMaxUSec'], self.seconds)
        values = cap_values({name:self.read(name) for name in ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group')})
        require(self.bounds is None or self.bounds == values)
        self.bounds = values
        members = self.read('cgroup.procs').splitlines()
        require(all(row.isdecimal() and int(row) > 1 for row in members) and str(self.pid) in members
            and len(members) <= TASKS and len(set(members)) == len(members))
        count = self.read('pids.current')
        require(count.isascii() and count.isdecimal() and 0 < int(count) <= TASKS)
        require('populated 1' in self.read('cgroup.events').splitlines())
        # Exec may change after Go; PID/start ticks/namespace remain frozen.
        current = kernel.process(self.pid)
        require(current[:2] == self.initial[:2] and not select.select([self.pidfd], [], [], 0)[0])
        self.anchored()

    def terminal(self, wait_status):
        require(type(wait_status) is int and self.exit_status is None
            and select.select([self.pidfd], [], [], 0)[0])
        require(os.WIFEXITED(wait_status) or os.WIFSIGNALED(wait_status))
        self.exit_status = os.waitstatus_to_exitcode(wait_status)
        return self.exit_status

    def stop_owned(self):
        """Reaping the original child does not transfer descendant ownership.

        Stop only after the original named anchor, frozen invocation, cgroup
        and admitted manager/kernel cap tuple all still match. Drift refuses.
        """
        kernel.remaining(self.manager.entry,self.manager.deadline,cleanup=True)
        require(self.anchored())
        facts=self.manager.show(cleanup=True)
        require(facts['LoadState']=='loaded' and facts['InvocationID']==self.invocation
            and facts['ControlGroup']==self.group and facts['MemoryMax']==str(MEMORY)
            and facts['MemorySwapMax']=='0' and facts['MemoryOOMGroup']=='yes'
            and facts['TasksMax']==str(TASKS) and facts['CPUQuotaPerSecUSec']=='1.9s')
        toolbar.verify_runtime(facts['RuntimeMaxUSec'],self.seconds)
        require(cap_values({name:self.read(name) for name in
            ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group')})==self.bounds)
        require(self.anchored())
        self.manager.stop(self.invocation)

    def cleanup(self):
        require(self.exit_status is not None)
        for _ in range(2):
            kernel.remaining(self.manager.entry, self.manager.deadline, cleanup=True)
            exists = self.anchored(allow_absent=True)
            facts = self.manager.show(cleanup=True)
            if exists:
                require(facts['LoadState'] == 'loaded' and facts['InvocationID'] == self.invocation
                    and facts['ControlGroup'] == self.group and facts['ActiveState'] in ('inactive','failed')
                    and not self.read('cgroup.procs') and 'populated 0' in self.read('cgroup.events').splitlines())
                cap_values({name:self.read(name) for name in ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group')})
            else:
                # Removed original anchored cgroup is empty by kernel removal
                # semantics. A reused name or a still-loaded unrelated unit refuses.
                require(facts['LoadState'] == 'not-found' and facts['ActiveState'] == 'inactive'
                    and not facts['InvocationID'] and not facts['ControlGroup'])
        return True

    def close(self):
        chain, self.chain = self.chain, []
        resident.close_owned_resources([row[1] for row in chain])


class ProjectEnvelope:
    """Cap the complete console/Bazel tree, including its orchestration parent.

    A destination-owned fresh slice and console scope must already have been
    prepared before the selected clock. No fallback to an uncontained console.
    The qualifier's child scope is placed beneath this SAME frozen slice.
    """
    def __init__(self, tools, entry, deadline):
        self.tools,self.entry,self.deadline=tools,entry,deadline
        self.chain=[]
        try:
            rows=yoga.file_bytes('/proc/self/cgroup',4096,deadline).decode('ascii').splitlines()
            require(len(rows)==1 and rows[0].startswith('0::/'))
            group=rows[0][3:]
            match=re.fullmatch(r'/(omuxyogaconsole([0-9a-f]{32})\.slice)/(omux-yoga-console-envelope-([0-9a-f]{32})\.scope)',group)
            require(match is not None and match[2]==match[4])
            self.project_slice,self.unit=match[1],match[3]
            self.group=group
            self.chain=kernel.open_chain(Path('/sys/fs/cgroup')/self.project_slice)
            self.invocation=None;self.bounds=None
            self.observe(bind_manager=False)
        except BaseException:
            self.close();raise

    def observe(self, *, cleanup=False, bind_manager=True):
        require(type(bind_manager) is bool)
        kernel.remaining(self.entry,self.deadline,cleanup=cleanup)
        for index,(path,fd,identity) in enumerate(self.chain):
            named=path.stat(follow_symlinks=False) if index==0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1],follow_symlinks=False)
            require(resident.stable(named)==identity==resident.stable(os.fstat(fd)))
        proxy=object.__new__(Scope);proxy.chain=self.chain
        values=cap_values({name:proxy.read(name) for name in
            ('memory.max','memory.swap.max','pids.max','cpu.max','memory.oom.group')})
        require(self.bounds is None or values==self.bounds);self.bounds=values
        require(yoga.file_bytes('/proc/self/cgroup',4096,self.deadline).decode('ascii').splitlines()==['0::'+self.group])
        # The initial kernel cap admission precedes runtime/NAR qualification.
        # No selected external tool executes until that proof has completed.
        if not bind_manager: return
        raw=call(self.tools['systemctl'],['--system','show','--property=Id,InvocationID,LoadState,ActiveState,ControlGroup',self.unit],
            self.entry,self.deadline,cleanup=cleanup)
        pairs=[row.split('=',1) for row in raw.decode('ascii').splitlines()]
        require(all(len(row)==2 for row in pairs) and len({row[0] for row in pairs})==len(pairs))
        facts=dict(pairs)
        require(set(facts)=={'Id','InvocationID','LoadState','ActiveState','ControlGroup'}
            and facts['Id']==self.unit and facts['LoadState']=='loaded' and facts['ActiveState']=='active'
            and facts['ControlGroup']==self.group and re.fullmatch('[0-9a-f]{32}',facts['InvocationID'])
            and (self.invocation is None or self.invocation==facts['InvocationID']))
        self.invocation=facts['InvocationID']
        require(yoga.file_bytes('/proc/self/cgroup',4096,self.deadline).decode('ascii').splitlines()==['0::'+self.group])

    def close(self):
        chain,self.chain=self.chain,[]
        resident.close_owned_resources([row[1] for row in chain])


def command(selection, source, output_base, arguments):
    request(arguments)
    require(Path(selection['sourceRoot']) == Path(source) and not Path(output_base).is_relative_to(source))
    return [selection['controllerTools']['bazel'], '--batch', '--nosystem_rc', '--nohome_rc',
        '--noworkspace_rc', '--output_base='+str(output_base),
        '--output_user_root='+str(Path(output_base).parent/'user-root'),
        '--server_javabase='+selection['controllerTools']['java_home'],
        'run', '--enable_bzlmod', '--lockfile_mode=error', '--repository_disable_download',
        '--remote_executor=', '--remote_cache=', '--disk_cache=', '--spawn_strategy=local',
        '--noremote_accept_cached', '--noremote_upload_local_results', LABEL, '--', *arguments[2:]]


def run(arguments, *, terminal_descriptor=0):
    selection_path, digest, output, deadline = request(arguments)
    uid, home = os.getuid(), Path(pwd.getpwuid(os.getuid()).pw_dir)
    selection = toolbar.selection(qualification.read_selection(selection_path, digest, deadline), deadline, uid, home)
    entry, deadline = toolbar.clock(selection, deadline)
    source = Path(selection['sourceRoot'])
    reservation, scope, pidfd, child, channel, run_fd, parent = None, None, None, None, None, None, None
    project, manager = None, None
    capture = None
    log, read_go = None, None
    result, waited, scope_cleaned, creation_requested, go_released = 125, False, False, False, False
    refusal = None
    try:
        project = ProjectEnvelope(selection['controllerTools'],entry,deadline)
        qualification.identity_capture(selection, deadline, uid, terminal_descriptor)
        require(qualification.graph_capture(source, deadline) == selection['sourceGraphSha256'])
        # Registered immutable tools are qualified before any external tool or
        # systemd DSO executes. Nothing is realized/installed/logged in here.
        yoga.runtime_qualification(selection, deadline)
        project.observe()
        import guard_yoga_installed_workspace as installed
        capture = installed.Capture(source, selection['installedWorkspace'], deadline, yoga.file_bytes)
        require({'yoga_local_console_scope.py','yoga_local_console_qualification.py'}
            .issubset(capture.record['controllerPackageSha256']))
        require(Path(__file__).resolve() == source/'tools/yoga_local_console_scope.py')
        capture.qualify(selection, selection['sourceGraphSha256'])
        terminal = terminal_identity(terminal_descriptor)
        parent = qualification.display.parent_descriptor(str(Path(output).parent), uid)
        parent_identity = resident.stable(os.fstat(parent))
        run_name = '.omux-yoga-console-'+str(uuid.uuid4())
        os.mkdir(run_name, 0o700, dir_fd=parent)
        run_fd = os.open(run_name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=parent)
        run_path = Path(output).parent/run_name
        for name in ('home','tmp'):
            os.mkdir(name, 0o700, dir_fd=run_fd)
        log = os.open('workload.log', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600, dir_fd=run_fd)
        os.fchmod(log, 0o600)
        read_go, write_go = os.pipe2(os.O_CLOEXEC)
        channel = write_go
        reservation = kernel.Witness(entry, deadline)
        seconds = math.floor(kernel.remaining(entry, deadline))
        require(1 <= seconds <= 1170)
        manager = Manager(selection['controllerTools'], 'omux-yoga-console-'+str(uuid.uuid4())+'.scope', entry, deadline, project.project_slice)
        absent = manager.show()
        require(absent['LoadState'] == 'not-found' and absent['ActiveState'] == 'inactive'
            and not absent['InvocationID'] and not absent['ControlGroup'])
        child = os.fork()
        if child == 0:
            try:
                os.close(write_go)
                # The sole child-side pre-Go operation is a bounded pipe wait.
                until = min(15, kernel.remaining(entry, deadline))
                require(select.select([read_go], [], [], until)[0] and os.read(read_go, 2) == b'G')
                os.close(read_go)
                os.dup2(terminal_descriptor, 0)
                os.dup2(log, 1); os.dup2(log, 2)
                for descriptor in (log, run_fd, parent):
                    if descriptor > 2: os.close(descriptor)
                # Keep the actual audit/login session; never allocate another TTY.
                libc = ctypes.CDLL(None)
                require(libc.prctl(38, 1, 0, 0, 0) == 0)  # PR_SET_NO_NEW_PRIVS
                os.chdir(source)
                environment = {'HOME':str(run_path/'home'), 'TMPDIR':str(run_path/'tmp'),
                    'TMP':str(run_path/'tmp'), 'TEMP':str(run_path/'tmp'), 'LANG':'C.UTF-8',
                    'JAVA_HOME':selection['controllerTools']['java_home'],
                    'OMUX_BAZEL_BOOTSTRAP_CLOSURE':selection['controllerTools']['bootstrap_closure'],
                    'PYTHONNOUSERSITE':'1', 'PYTHONDONTWRITEBYTECODE':'1', 'PYTHONHASHSEED':'0'}
                argv = command(selection, source, run_path/'output-base', arguments)
                os.execve(argv[0], argv, environment)
            except BaseException:
                os._exit(125)
        os.close(read_go); read_go = None
        os.close(log); log = None
        pidfd = os.pidfd_open(child, 0)
        creation_requested = True
        manager.create(child, seconds)
        scope = Scope(manager, child, pidfd, seconds)
        # Frozen scope, inherited descriptor/session, source and resident all
        # match before the exact worker is permitted to execute any tool.
        qualification.identity_capture(selection, deadline, uid, terminal_descriptor)
        recheck_terminal(terminal_descriptor, terminal)
        capture.qualify(selection, selection['sourceGraphSha256'])
        require(resident.stable(os.fstat(parent)) == parent_identity)
        project.observe();release_go(write_go, scope, reservation)
        go_released = True
        os.close(write_go); channel = None
        while True:
            left = kernel.remaining(entry, deadline)
            if select.select([pidfd], [], [], min(1, left))[0]: break
            qualification.identity_capture(selection, deadline, uid, terminal_descriptor)
            recheck_terminal(terminal_descriptor, terminal)
            require(qualification.read_selection(selection_path, digest, deadline) == selection)
            capture.qualify(selection, selection['sourceGraphSha256'])
            project.observe();reservation.observe(); scope.observe()
        pid, status = os.waitpid(child, 0)
        require(pid == child); waited = True
        result = scope.terminal(status)
        empty = scope.cleanup();scope_cleaned = True
        capture.qualify(selection, selection['sourceGraphSha256'])
        qualification.identity_capture(selection, deadline, uid, terminal_descriptor)
        recheck_terminal(terminal_descriptor, terminal)
        require(qualification.read_selection(selection_path, digest, deadline) == selection)
        project.observe(cleanup=True);resident_after = reservation.observe(cleanup=True)
        produced_sha = None
        if result == 0:
            raw = yoga.file_bytes(output, qualification.MAX_SELECTION, deadline, private=True)
            receipt = yoga.decode(raw)
            toolbar.schema(receipt, deadline, str(source), selection['controllerTools'], selection['sourceGraphSha256'], uid)
            require(all(receipt.get(key) == value for key,value in selection.items() if key not in ('scope','host')))
            capture.qualify(receipt, selection['sourceGraphSha256'])
            produced_sha = hashlib.sha256(raw).hexdigest()
        kernel.remaining(entry, deadline, cleanup=True)
        return {'scope':'yoga-local-console-qualification-scope-v1','exit':result if result >= 0 else 125,
            'qualificationProduced':result == 0, 'ownedCleanupEmpty':empty,
            'originalEntryMonotonicNs':entry, 'deadlineMonotonicNs':deadline,
            'workerExitCode':result, 'terminalCustodyRetained':True,
            'workerPid':child, 'workerStartTicks':scope.initial[0], 'workerPidfdExitReady':True,
            'scopeUnit':scope.manager.unit, 'scopeInvocationId':scope.invocation,
            'scopeKernelBounds':dict(scope.bounds), 'qualificationReceiptSha256':produced_sha,
            'projectSlice':project.project_slice,'consoleEnvelopeUnit':project.unit,
            'consoleEnvelopeInvocationId':project.invocation,
            'consoleEnvelopeCleanupQualified':False,
            'residentReservation':resident_after, 'executionAuthority':False,
            'toolbarConsentProved':False, 'installationQualified':False,
            'nativeQualified':False, 'continuityQualified':False,'liveQualified':False,
            'sdkQualified':False,'schemaQualified':False,'compilerQualified':False,
            'custodyQualified':False,'healthQualified':False,'contextRotation':False,
            'daemonContextAcquisition':False,'providerLogin':False,'displayGuess':False}
    except BaseException:
        refusal = Refusal(refusal_projection(manager,scope,creation_requested,go_released,waited,scope_cleaned))
        raise refusal from None
    finally:
        # Refusal never opens Go. An unexecuted child receives EOF and exits125.
        failures = []
        def finish(operation):
            try: operation()
            except BaseException as error: failures.append(error)
        def terminate():
            nonlocal waited,scope_cleaned
            def mark_reaped():
                nonlocal waited
                waited=True
            scope_cleaned=terminate_child(child,pidfd,scope,waited,scope_cleaned,entry,deadline,mark_reaped)
        if channel is not None: finish(lambda: os.close(channel))
        finish(terminate)
        if scope is not None: finish(scope.close)
        if pidfd is not None: finish(lambda: os.close(pidfd))
        if reservation is not None: finish(reservation.close)
        if project is not None: finish(project.close)
        if capture is not None: finish(capture.close)
        for descriptor in (read_go,log,run_fd,parent):
            if descriptor is not None: finish(lambda selected=descriptor: os.close(selected))
        if failures:
            raise Refusal(refusal_projection(manager,scope,creation_requested,go_released,waited,scope_cleaned)) from None
        if refusal is not None:
            refusal.projection=refusal_projection(manager,scope,creation_requested,go_released,waited,scope_cleaned)


def refusal_projection(manager,scope,creation_requested,go_released,waited,scope_cleaned):
    return {'scope':'yoga-local-console-qualification-refused-v1','exit':125,
        'scopeUnit':None if manager is None else manager.unit,
        'scopeInvocationId':None if scope is None else scope.invocation,
        'initialScopeOwnershipVerified':scope is not None,'creationRequested':creation_requested,
        'goReleased':go_released,'originalChildReaped':waited,
        'ownedCleanupEmpty':scope_cleaned,'consoleEnvelopeCleanupQualified':False,
        'qualificationProduced':False,'executionAuthority':False,'toolbarConsentProved':False,
        'nativeQualified':False,'sdkQualified':False,'schemaQualified':False,
        'compilerQualified':False,'custodyQualified':False,'healthQualified':False,
        'liveQualified':False,'continuityQualified':False}
