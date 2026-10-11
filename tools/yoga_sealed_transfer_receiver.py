"""Bounded, independently observed receiver for one digest-selected public tree."""
import hashlib
import os
from pathlib import Path
import stat
import sys
import time
import yoga_install_inputs_receiver as base
import yoga_sealed_transfer_schema as schema
import guard_native_seed_plan_reserved as resident

SCOPE = 'omux-yoga-sealed-workspace-stage-v1'
PARENT = schema.PARENT
INPUT_SHA256 = None  # Replaced only by the digest-bound external bootstrap.

def checked_input(raw, token):
    value = schema.manifest(raw, INPUT_SHA256)
    schema.require(value['transferId'] == token)
    return value

def result(value, phase):
    rows = schema.member_rows(value)
    return {'scope': SCOPE, 'phase': phase, 'inputSha256': INPUT_SHA256,
            'files': len(rows), 'bytes': sum(row[1] for row in rows),
            'destinationRehashed': True, 'installation': False,
            'destinationRegistrationVerified': False, 'seatQualified': False,
            'toolbarConsentProved': False}

class Transaction(base.Transaction):
    """Inherited held-inode cleanup; a fresh UUID tree, no archive extraction."""
    def __init__(self, deadline, raw, token):
        self.deadline, self.cleanup_deadline = deadline, deadline + base.RESERVE_NS
        self.parent, self.created, self.dirs, self.leaves = None, [], [], []
        self.published, self.raw, self.token = False, raw, token
        self.value = checked_input(raw, token)
        self.rows = schema.member_rows(self.value)
        self.parents = {}
        try:
            self.parent = base.Directory(PARENT, deadline, leaf_private=True)
            absent(self.parent, token)
            free = os.fstatvfs(self.parent.fd)
            schema.require(free.f_bavail * free.f_frsize >= 2 *
                (sum(row[1] for row in self.rows) + len(raw)))
        except BaseException:
            self.close(); raise

    def create(self):
        self.parent.check(); absent(self.parent, self.token)
        self.mkdir(self.parent.fd, self.token)
        self.parents[''] = self.dirs[-1][1]
        names = set()
        for name, *_ in self.rows:
            parts = Path(name).parts[:-1]
            names.update('/'.join(parts[:index+1]) for index in range(len(parts)))
        for name in sorted(names, key=lambda value:(len(Path(value).parts), value)):
            parent, leaf = str(Path(name).parent), Path(name).name
            self.mkdir(self.parents['' if parent == '.' else parent], leaf)
            self.parents[name] = self.dirs[-1][1]
        self.check()

    def leaf(self, name, size, digest, mode, incoming=None, raw=None):
        directory = str(Path(name).parent)
        parent = self.parents['' if directory == '.' else directory]
        leaf, temporary = Path(name).name, '.' + Path(name).name + '.receiving'
        fd = os.open(temporary, os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600, dir_fd=parent)
        held = {'parent': parent, 'names': [temporary], 'fd': fd, 'pin': base.identity(os.fstat(fd))}
        self.leaves.append(held)
        actual, count = hashlib.sha256(), 0
        while count < size:
            self.check()
            data = raw[count:count+base.FRAME] if raw is not None else base.exact(incoming, min(base.FRAME, size-count), self.deadline)
            schema.require(bool(data) and len(data) <= size-count)
            actual.update(data); base.write_all(fd, data, self.deadline); count += len(data)
        schema.require(count == size and actual.hexdigest() == digest)
        os.fsync(fd)
        schema.require(held['pin'] == base.identity(os.fstat(fd)) ==
            base.identity(os.stat(temporary, dir_fd=parent, follow_symlinks=False)))
        os.fchmod(fd, mode)
        held['pin'] = base.identity(os.fstat(fd))
        base.hash_leaf(parent, temporary, size, digest, self.deadline, mode)
        self.check()
        os.link(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        held['names'].append(leaf)
        schema.require(os.fstat(fd).st_nlink == 2 and held['pin'] ==
            base.identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)))
        os.unlink(temporary, dir_fd=parent); held['names'].remove(temporary)
        os.fsync(parent)
        base.hash_leaf(parent, leaf, size, digest, self.deadline, mode)

    def receive(self, incoming):
        self.create()
        for name, size, digest, mode in self.rows:
            schema.require(base.line(incoming, self.deadline) ==
                {'role': name, 'bytes': size, 'sha256': digest})
            self.leaf(name, size, digest, mode, incoming=incoming)
        schema.require(base.line(incoming, self.deadline) == {'end': SCOPE})
        # External transfer authority is published last, outside sealed workspace.
        self.leaf('transfer-input.json', len(self.raw), INPUT_SHA256, 0o444, raw=self.raw)
        self.readback(); self.published = True
        return result(self.value, 'worker-readback')

    def readback(self):
        self.check()
        rows = self.rows + [('transfer-input.json',len(self.raw),INPUT_SHA256,0o444)]
        for directory, fd in self.parents.items():
            expected = {Path(name[len(directory)+1:] if directory else name).parts[0]
                        for name,*_ in rows if not directory or name.startswith(directory+'/')}
            schema.require(set(os.listdir(fd)) == expected)
        for name,size,digest,mode in rows:
            parent = str(Path(name).parent)
            base.hash_leaf(self.parents['' if parent == '.' else parent], Path(name).name,
                           size,digest,self.deadline,mode)
        self.check()

def absent(parent, token):
    parent.check()
    try: os.stat(token, dir_fd=parent.fd, follow_symlinks=False)
    except FileNotFoundError: return
    raise ValueError('sealed-transfer-refused')

def destination_readback(token, deadline):
    root = base.Directory(Path(PARENT)/token, deadline, leaf_private=True)
    held = [root]
    try:
        fd = os.open('transfer-input.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=root.fd)
        try:
            info = os.fstat(fd)
            schema.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o444
                and 0 < info.st_size <= schema.MAX_METADATA)
            raw = b''
            while len(raw) < info.st_size:
                base.tick(deadline); data = os.read(fd,min(base.FRAME,info.st_size-len(raw)))
                schema.require(bool(data)); raw += data
            schema.require(base.file_identity(info) == base.file_identity(os.fstat(fd)) ==
                base.file_identity(os.stat('transfer-input.json',dir_fd=root.fd,follow_symlinks=False)))
        finally: os.close(fd)
        value = checked_input(raw, token)
        rows = schema.member_rows(value)+[('transfer-input.json',len(raw),INPUT_SHA256,0o444)]
        directories = {'':root}
        names = {str(Path(name).parent) for name,*_ in rows}
        names |= {'/'.join(Path(name).parts[:index]) for name,*_ in rows for index in range(1,len(Path(name).parts))}
        for name in sorted(names-{'.'},key=lambda item:(len(Path(item).parts),item)):
            current = base.Directory(Path(PARENT)/token/name,deadline,leaf_private=True)
            directories[name] = current; held.append(current)
        for name,current in directories.items():
            expected={Path(path[len(name)+1:] if name else path).parts[0] for path,*_ in rows
                      if not name or path.startswith(name+'/')}
            schema.require(set(os.listdir(current.fd)) == expected)
            current.check()
        for name,size,digest,mode in rows:
            parent=str(Path(name).parent)
            base.hash_leaf(directories['' if parent=='.' else parent].fd,Path(name).name,size,digest,deadline,mode)
        for current in held: current.check()
        return value
    finally:
        failed=False
        for current in reversed(held):
            try: current.close()
            except BaseException: failed=True
        schema.require(not failed)

def worker(token, deadline):
    base.unit_name(token); base.tick(deadline)
    os.set_blocking(0,False); os.set_blocking(1,False)
    import signal
    def cancelled(signum,frame): raise ValueError('sealed-transfer-refused')
    for signum in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT): signal.signal(signum,cancelled)
    schema.require(base.line(0,deadline) == {'go':token,'scope':SCOPE,'inputSha256':INPUT_SHA256})
    frame=base.line(0,deadline)
    schema.require(type(frame) is dict and set(frame)=={'bytes','sha256'}
        and type(frame['bytes']) is int and 0<frame['bytes']<=schema.MAX_METADATA and frame['sha256']==INPUT_SHA256)
    raw=base.exact(0,frame['bytes'],deadline)
    transaction=Transaction(deadline,raw,token)
    try: base.emit(1,transaction.receive(0),deadline)
    finally: transaction.close()

def receiver_command(token, deadline, source):
    command,runtime=base.receiver_command(token,deadline,source)
    previous='ReadWritePaths='+base.PARENT
    schema.require(command.count(previous)==1)
    command[command.index(previous)]='ReadWritePaths='+PARENT
    return command,runtime

def verify_unit(actual,token,runtime):
    schema.require(actual['ReadWritePaths']==PARENT)
    projected=dict(actual,ReadWritePaths=base.PARENT)
    pid,path=base.verify_unit(projected,token,runtime)
    # Existing receiver accepts max-only runtime. New route requires exact readback.
    schema.require(base.duration(actual['RuntimeMaxUSec'])==runtime)
    return pid,path

def recheck_caps(cgroup,pid,deadline):
    cgroup.check()
    expected={'memory.max':'268435456','memory.swap.max':'0','pids.max':'32',
              'cpu.max':'10000 100000','cgroup.procs':str(pid)}
    for name,value in expected.items():
        base.tick(deadline)
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=cgroup.fd)
        try:
            raw=os.read(fd,4097)
            schema.require(len(raw)<=4096 and os.read(fd,1)==b'' and raw.decode('ascii').strip()==value)
        finally: os.close(fd)
    cgroup.check()

# Reuse qualified process/unit/IO primitives without modifying their globals.
unit_name = base.unit_name
validate_remote_clock = base.validate_remote_clock
TOOLS = base.TOOLS
require = base.require
Directory = base.Directory
stat = base.stat
re = base.re
FRAME = base.FRAME
file_identity = base.file_identity
identity = base.identity
session_peer = base.session_peer
show = base.show
subprocess = base.subprocess
manager_environment = base.manager_environment
tick = base.tick
selectors = base.selectors
receiver_process = base.receiver_process
cgroup_pin = base.cgroup_pin
emit = base.emit
RESERVE_NS = base.RESERVE_NS
MAX_NS = base.MAX_NS

def coordinator(token, remote_timestamp, deadline, source, tool_pins):
    """Called by exact OS bootstrap only after authenticated OS+NAR closure checks."""
    import fcntl
    witness = resident.Witness(deadline + RESERVE_NS - MAX_NS, deadline + RESERVE_NS)
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
        parent = Directory(PARENT, deadline, leaf_private=True)
        fcntl.flock(parent.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        absent(parent, token)
        peer = session_peer(deadline)
        witness.observe()
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
        recheck_caps(cgroup,pid,deadline)
        parent.check()
        absent(parent, token)
        require(peer == session_peer(deadline), 'local-manager-peer-changed')
        witness.observe()
        emit(1, {'scope': SCOPE, 'phase': 'go-ready', 'token': token,
                 'pid': pid, 'start': pin[1], 'uid': pin[2],
                 'caps_verified': True, 'physical_parent_verified': True,
                 'inputSha256': INPUT_SHA256}, deadline)
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
            schema.require(verify_unit(actual,token,runtime_us)==(pid,path))
            recheck_caps(cgroup,pid,deadline)
            witness.observe()
            with selectors.DefaultSelector() as selector:
                selector.register(runner.stderr, selectors.EVENT_READ)
                if selector.select(min(0.05, tick(deadline))):
                    require(not os.read(runner.stderr.fileno(), 4096), 'receiver-diagnostic-refused')
        destination_readback(token, deadline)
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
                runner.wait(timeout=min(15,tick(cleanup_deadline)))
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
    if failure is not None or not success or not cleanup:
        witness.close()
    require(failure is None and success and cleanup, 'receiver-staging-refused')
    try:
        value = destination_readback(token, deadline + RESERVE_NS)
        witness.observe(cleanup=True)
    finally:
        witness.close()
    emit(1, dict(result(value, 'complete'), token=token,
                 receiverCleanupVerified=True), deadline + RESERVE_NS)


SYSTEMCTL=base.SYSTEMCTL
SHOW=base.SHOW
properties=base.properties
process=base.process

def bounded(command,deadline,maximum=32768,**kwargs):
    cutoff=min(deadline,time.monotonic_ns()+15*10**9)
    kwargs["cleanup_deadline"]=min(kwargs.get("cleanup_deadline") or deadline+RESERVE_NS,cutoff)
    return base.bounded(command,cutoff,maximum,**kwargs)

def show(token, deadline, *, missing=False, cleanup_deadline=None):
    status, raw = bounded([SYSTEMCTL, '--user', 'show', unit_name(token),
                           '--property=' + ','.join(SHOW)], deadline,
                          accept=(0, 4) if missing else (0,),
                          cleanup_deadline=cleanup_deadline, return_status=True)
    value = properties(raw)
    require(status == 0 or missing and status == 4 and value['LoadState'] == 'not-found',
            'receiver-unit-error-status')
    return value

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
