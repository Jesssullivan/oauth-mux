"""Exact N10 content-source/HUB cohort; no ancestor, Rust or capability admission."""
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid
import guard_cache as cache
import guard_native_seed_plan_reserved as kernel

PROFILE = "native-siwc-catalog-content-source-reserved"
INPUT_MODE = "native-file-writer-models-reserved"
PROFILES = (PROFILE,)
ARGUMENTS = ["test", "//tools:codex_native_siwc_catalog_content_source_test",
    "//tools:codex_native_siwc_catalog_content_source_producer"]
MODE = "OMUX_NATIVE_FILE_WRITER_MODELS_MODE"
ENTRY = "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS"
DEADLINE = "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS"
EPOCH = "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH"
SOURCE = "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT"
GRAPH = "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256"
ACTION_SECONDS = 840
DEPENDENCY_SCOPE = "fixed-siwc-content-dependency-state-v1"
DELIVERY_ARGUMENTS = ["test", "//tools:codex_native_siwc_content_delivery_producer"]
DELIVERY_REQUEST = "OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST"
DELIVERY_REQUEST_SHA256 = DELIVERY_REQUEST + "_SHA256"
MEMORY, TASKS, CPU = kernel.MEMORY, kernel.TASKS, kernel.CPU
Witness = kernel.Witness
cleanup_retained = kernel.cleanup_retained
properties = kernel.properties
remaining = kernel.remaining


def require(value):
    if value is not True:
        raise ValueError("native-file-writer-models-reservation-refused")


def selected(profile, arguments):
    require(profile == PROFILE and arguments == ARGUMENTS)
    return {"PrivateNetwork": "yes"}


def _witness(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class ContentDependencyLease(cache.CacheLease):
    """Dependency state only; producer/SDK/output readiness is never inherited.

    The coordinator holds this exact owner through fresh execution, terminal
    evidence and independently authenticated per-epoch publication. Normal
    dependency writes may change output-base directory times; capture freezes
    its full witness only after the owned workload and cleanup have ended.
    """
    def __init__(self, state_root, key, run_id, *, checkout, source_commit,
                 graph_sha256, entry, deadline):
        require(Path(state_root) in kernel.resident.PUBLIC_ROOTS
            and type(entry) is int and type(deadline) is int
            and deadline-entry == 1200*10**9
            and type(source_commit) is str and re.fullmatch(r"[0-9a-f]{40}",source_commit) is not None
            and type(graph_sha256) is str and re.fullmatch(r"[0-9a-f]{64}",graph_sha256) is not None)
        self.checkout = Path(checkout)
        require(self.checkout.is_absolute() and self.checkout.resolve(strict=True) == self.checkout
            and str(self.checkout) == os.path.normpath(str(self.checkout)))
        super().__init__(state_root,key,run_id,policy_version=2)
        self.source_commit,self.graph_sha256,self.entry,self.deadline = source_commit,graph_sha256,entry,deadline
        self.base_fd = self.marker_fd = self.checkout_fd = self.state_fd = None
        self.capture_ready = self.active = self.entered = False
        self.pid,self.thread = os.getpid(),threading.get_ident()
        self.binding = self._binding()

    def _binding(self):
        return (str(self.state_root),self.key,self.name,self.run_id,str(self.output_base),
                str(self.checkout),self.source_commit,self.graph_sha256,self.entry,self.deadline,self.policy_version)

    def _clock(self):
        require(type(self) is ContentDependencyLease and self.active and self.binding == self._binding()
            and self.pid == os.getpid() and self.thread == threading.get_ident()
            and self.entry <= time.monotonic_ns() < (self.deadline-30*10**9 if self.capture_ready else self.entry+600*10**9)
            and time.monotonic_ns() < self.deadline)

    def __enter__(self):
        require(not self.active and not self.capture_ready and not self.entered)
        self.entered = True
        try:
            self.state_fd = cache.trusted_directory(self.state_root)
            created = False
            try:
                os.mkdir(self.name,mode=0o700,dir_fd=self.state_fd)
                created = True
            except FileExistsError: pass
            self.directory = os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.state_fd)
            directory = os.fstat(self.directory)
            require(directory.st_uid == os.getuid() and stat.S_IMODE(directory.st_mode) == 0o700)
            self.lock = os.open('cache.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.directory)
            info = os.fstat(self.lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if created:
                cache.write_marker(self.directory,{'schema':2,'key':self.key,'clean':True,
                    'last_run':None,'cleanup_receipt_sha256':None})
            previous = cache.read_marker(self.directory)
            require(set(previous) == {'schema','key','clean','last_run','cleanup_receipt_sha256'}
                and previous['schema'] == 2 and previous['key'] == self.key and previous['clean'] is True)
            if previous['last_run'] is not None:
                self._receipt(previous['last_run'],previous['cleanup_receipt_sha256'],previous=True)
            else: require(created and previous['cleanup_receipt_sha256'] is None)
            cache.write_marker(self.directory,{'schema':2,'key':self.key,'clean':False,
                'last_run':self.run_id,'cleanup_receipt_sha256':None})
            self.checkout_fd = os.open(self.checkout,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            info = os.fstat(self.checkout_fd)
            require(info.st_uid == os.getuid() and not info.st_mode & 0o022)
            self.checkout_anchor = _witness(info)
            try: os.mkdir('output-base',mode=0o700,dir_fd=self.directory)
            except FileExistsError: pass
            self.base_fd = os.open('output-base',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.directory)
            base = os.fstat(self.base_fd)
            require(base.st_uid == os.getuid() and not base.st_mode & 0o022)
            self.base_anchor = _witness(base)
            self.marker_fd = os.open('owner.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.directory)
            self.marker_anchor = _witness(os.fstat(self.marker_fd))
            self.marker_value = {'schema':2,'key':self.key,'clean':False,
                'last_run':self.run_id,'cleanup_receipt_sha256':None}
            self.directory_anchor = _witness(os.fstat(self.directory))
            self.lock_anchor = _witness(os.fstat(self.lock))
            self.state_anchor = _witness(os.fstat(self.state_fd))[:5]
            self.active = True
            self.fence()
            return self
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: raise error from cleanup
            raise

    def _named(self):
        require(self.checkout.resolve(strict=True) == self.checkout
            and _witness(os.fstat(self.checkout_fd)) == self.checkout_anchor == _witness(
                os.stat(self.checkout,follow_symlinks=False))
            and _witness(os.fstat(self.state_fd))[:5] == self.state_anchor == _witness(
                os.stat(self.state_root,follow_symlinks=False))[:5]
            and _witness(os.fstat(self.directory)) == self.directory_anchor == _witness(
                os.stat(self.name,dir_fd=self.state_fd,follow_symlinks=False))
            and _witness(os.fstat(self.lock)) == self.lock_anchor == _witness(
                os.stat('cache.lock',dir_fd=self.directory,follow_symlinks=False))
            and _witness(os.fstat(self.marker_fd)) == self.marker_anchor == _witness(
                os.stat('owner.json',dir_fd=self.directory,follow_symlinks=False)))
        current = _witness(os.fstat(self.base_fd))
        require(current == _witness(os.stat('output-base',dir_fd=self.directory,follow_symlinks=False))
            and current[:5] == self.base_anchor[:5]
            and (not self.capture_ready or current == self.capture_anchor))

    def fence(self):
        self._clock()
        self._named()
        require(cache.read_marker(self.directory) == self.marker_value)
        # IO above may trigger a mutation. Named + held joins follow that IO,
        # including the checkout, marker, cache parent and output-base.
        self._named()
        self._clock()

    def prepare_capture(self):
        require(not self.capture_ready)
        self.capture_anchor = _witness(os.fstat(self.base_fd))
        self.capture_ready = True
        self.fence()

    def facts(self):
        self.fence()
        return {'kind':'omux-native-siwc-content-dependency-lease-v1','key':self.key,'namespace':self.name,
            'output_base':str(self.output_base),'run_id':self.run_id,'checkout':str(self.checkout),
            'source_commit':self.source_commit,'graph_sha256':self.graph_sha256,
            'entry_monotonic_ns':self.entry,'deadline_monotonic_ns':self.deadline}

    def _receipt(self,run_id,pin,*,previous=False):
        require(type(pin) is str and re.fullmatch(r'[0-9a-f]{64}',pin) is not None
            and str(uuid.UUID(run_id)) == run_id)
        parent = cache.trusted_directory(self.state_root)
        run = fd = None
        primary = None
        try:
            parent_anchor=_witness(os.fstat(parent))
            require(parent_anchor == _witness(os.stat(self.state_root,follow_symlinks=False)))
            run = os.open(run_id,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            run_anchor=_witness(os.fstat(run))
            require(stat.S_ISDIR(run_anchor[4]) and run_anchor[2] == os.getuid()
                and stat.S_IMODE(run_anchor[4]) == 0o700
                and run_anchor == _witness(os.stat(run_id,dir_fd=parent,follow_symlinks=False)))
            fd = os.open('receipt.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=run)
            before = _witness(os.fstat(fd))
            require(stat.S_ISREG(before[4]) and before[2] == os.getuid() and before[5] == 1
                and stat.S_IMODE(before[4]) == 0o600 and 0 < before[6] <= 1024*1024)
            chunks=[]; total=0
            while True:
                block=os.read(fd,65536)
                if not block: break
                total += len(block); require(total <= before[6]); chunks.append(block)
            raw=b''.join(chunks)
            require(total == before[6] and hashlib.sha256(raw).hexdigest() == pin
                and _witness(os.fstat(fd)) == before == _witness(os.stat('receipt.json',dir_fd=run,follow_symlinks=False)))
            require(parent_anchor == _witness(os.fstat(parent)) == _witness(os.stat(self.state_root,follow_symlinks=False))
                and run_anchor == _witness(os.fstat(run)) == _witness(os.stat(run_id,dir_fd=parent,follow_symlinks=False)))
            receipt=json.loads(raw)
            disposition=receipt['native_siwc_content_dependency_disposition']
            require(receipt['id'] == run_id and receipt['profile'] == PROFILE
                and receipt['cache_key'] == self.key and receipt['cache_policy'] == 2
                and receipt['cache_reuse_requested'] is True
                and receipt['descendants_empty'] is True
                and receipt['cleanup']['ownership'] == 'verified' and receipt['cleanup']['state'] == 'empty'
                and receipt['cleanup']['readback_attempts'] >= 2
                and receipt['test_evidence']['state'] == 'preserved'
                and disposition == {'kind':'omux-native-siwc-content-dependency-disposition-v1',
                    'state':('dependency-only-after-owned-source-failure' if receipt['workload_exit'] != 0
                        else 'dependencies-after-owned-source-and-delivery-success'),
                    'checkout':str(self.checkout),'key':self.key,
                    'source_qualified_by_disposition':False,'delivery_qualified_by_disposition':False,
                    'native_runtime_qualified':False})
            if receipt['workload_exit'] != 0:
                require(type(receipt['workload_exit']) is int and receipt['exit'] != 0
                    and receipt.get('native_siwc_content_publication') is None
                    and receipt.get('source_phase_receipt') is None
                    and receipt.get('native_siwc_content_delivery') is None)
            else:
                require(receipt['exit'] == 0 and type(receipt['native_siwc_content_publication']) is dict
                    and type(receipt['source_phase_receipt']) is dict
                    and receipt['native_siwc_content_delivery']['exit'] == 0)
            if not previous:
                require(receipt['source_commit'] == self.source_commit and receipt['graph_sha256'] == self.graph_sha256)
            return receipt
        except BaseException as error:
            primary=error; raise
        finally:
            failure=None
            for owned in (fd,run,parent):
                if owned is not None:
                    try: os.close(owned)
                    except BaseException as error:
                        if failure is None: failure=error
            if failure is not None:
                if primary is not None: raise primary from failure
                raise failure
            if primary is None:
                # After every close attempt, the receipt must still have its
                # canonical named role. No newly opened descriptor is needed.
                require(self.state_root.resolve(strict=True) == self.state_root
                    and parent_anchor == _witness(os.fstat(self.state_fd)) == _witness(
                        os.stat(self.state_root,follow_symlinks=False))
                    and run_anchor == _witness(os.stat(run_id,dir_fd=self.state_fd,follow_symlinks=False))
                    and before == _witness(os.stat(self.state_root/run_id/'receipt.json',follow_symlinks=False))
                    and run_anchor == _witness(os.stat(run_id,dir_fd=self.state_fd,follow_symlinks=False)))

    def disposition(self,receipt):
        self.fence()
        require(self.capture_ready and receipt['descendants_empty'] is True
            and receipt['cleanup']['ownership'] == 'verified' and receipt['cleanup']['state'] == 'empty'
            and receipt['cleanup']['readback_attempts'] >= 2
            and receipt['test_evidence']['state'] == 'preserved')
        failed=receipt['workload_exit'] != 0
        require((failed and receipt['exit'] != 0 and receipt.get('native_siwc_content_delivery') is None
                and receipt.get('native_siwc_content_publication') is None and receipt.get('source_phase_receipt') is None)
            or (not failed and receipt['exit'] == 0 and receipt['native_siwc_content_delivery']['exit'] == 0
                and type(receipt['native_siwc_content_publication']) is dict))
        return {'kind':'omux-native-siwc-content-dependency-disposition-v1',
            'state':('dependency-only-after-owned-source-failure' if failed else
                'dependencies-after-owned-source-and-delivery-success'),
            'checkout':str(self.checkout),'key':self.key,'source_qualified_by_disposition':False,
            'delivery_qualified_by_disposition':False,'native_runtime_qualified':False}

    def complete(self,descendants_empty,cleanup_receipt_sha256):
        self.fence()
        require(self.capture_ready and descendants_empty is True)
        self._receipt(self.run_id,cleanup_receipt_sha256)
        self.fence()
        marker=dict(self.marker_value,clean=True,cleanup_receipt_sha256=cleanup_receipt_sha256)
        raw=(json.dumps(marker,sort_keys=True)+'\n').encode()
        temporary='.owner-'+str(uuid.uuid4()); creator=None
        primary=None
        try:
            creator=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.directory)
            position=0
            while position<len(raw):
                written=os.write(creator,raw[position:]); require(written>0); position+=written
            os.fsync(creator)
            before=_witness(os.fstat(creator))
            require(before[2] == os.getuid() and before[5] == 1 and stat.S_IMODE(before[4]) == 0o600)
            os.rename(temporary,'owner.json',src_dir_fd=self.directory,dst_dir_fd=self.directory)
            os.fsync(self.directory)
            after=_witness(os.fstat(creator))
            require(before[:8] == after[:8] and after == _witness(os.stat('owner.json',dir_fd=self.directory,follow_symlinks=False))
                and os.pread(creator,len(raw)+1,0) == raw)
            current=_witness(os.fstat(self.directory))
            require(current[:5] == self.directory_anchor[:5] and current == _witness(
                os.stat(self.name,dir_fd=self.state_fd,follow_symlinks=False)))
            old,self.marker_fd=self.marker_fd,creator; creator=None
            self.marker_anchor,self.directory_anchor,self.marker_value=after,current,marker
            os.close(old)  # detached first: numeric descriptor is never retried.
            self.fence()
        except BaseException as error:
            primary=error; raise
        finally:
            if creator is not None:
                try: os.close(creator)
                except BaseException as cleanup:
                    if primary is not None: raise primary from cleanup
                    raise

    def close(self):
        self.active = False
        owned = [self.marker_fd,self.base_fd,self.checkout_fd,self.state_fd,self.lock,self.directory]
        self.marker_fd = self.base_fd = self.checkout_fd = self.state_fd = self.lock = self.directory = None
        failure = None
        for fd in owned:
            if fd is not None:
                try: os.close(fd)
                except BaseException as error:
                    if failure is None: failure = error
        if failure is not None: raise failure


def resident_continuity(initial,final):
    """Fresh actual samples may advance count; no SOURCE clock/proof changes."""
    require(type(initial) is dict and type(final) is dict and set(initial)==set(final)
        and type(initial.get('observations')) is int and type(final.get('observations')) is int
        and 1 <= initial['observations'] <= final['observations'] <= 65535
        and {key:value for key,value in initial.items() if key!='observations'} ==
            {key:value for key,value in final.items() if key!='observations'})
    kernel.kernel_bounds(initial['kernel_bounds'])
    kernel.kernel_bounds(final['kernel_bounds'])


def delivery_identity(run):
    require(isinstance(run,Path) and run.parent in kernel.resident.PUBLIC_ROOTS
        and str(uuid.UUID(run.name)) == run.name and run.resolve(strict=True) == run)
    identifier = str(uuid.uuid5(uuid.UUID(run.name),'omux-native-siwc-content-delivery-v1'))
    return identifier,'omux-execution-'+identifier+'.service'


def delivery_seconds(entry,deadline,*,sample_ns=None):
    require(type(entry) is int and type(deadline) is int and deadline-entry == 1200*10**9)
    current = time.monotonic_ns() if sample_ns is None else sample_ns
    require(type(current) is int and entry <= current <= time.monotonic_ns() < deadline-30*10**9)
    seconds = min(ACTION_SECONDS,(deadline-30*10**9-current)//10**9)
    require(seconds >= 1)
    return seconds


def delivery_command(builder,bazel,run,entry,deadline,request_sha256,*,source_commit,
                     graph_sha256,seconds,sample_ns,repository_cache=None,nixpkgs_source=None):
    delivery_identity(run)
    require(type(seconds) is int and 1 <= seconds <= ACTION_SECONDS
        and seconds == delivery_seconds(entry,deadline,sample_ns=sample_ns)
        and type(source_commit) is str and re.fullmatch(r'[0-9a-f]{40}',source_commit) is not None
        and type(graph_sha256) is str and re.fullmatch(r'[0-9a-f]{64}',graph_sha256) is not None
        and type(request_sha256) is str and re.fullmatch(r'[0-9a-f]{64}',request_sha256) is not None)
    result = builder(bazel,run,DELIVERY_ARGUMENTS,profile='standard',
        source_commit=source_commit,source_dirty='false',repository_cache=repository_cache,
        nixpkgs_source=nixpkgs_source,output_base=run/'delivery-output-base')
    require(sum(value.startswith('--output_user_root=') for value in result) == 1
        and sum(value.startswith('--symlink_prefix=') for value in result) == 1
        and '--nocache_test_results' in result and '--remote_executor=' in result and '--remote_cache=' in result)
    result = [('--output_user_root='+str(run/'delivery-user-root')) if value.startswith('--output_user_root=') else
        ('--symlink_prefix='+str(run/'delivery-evidence/bazel-')) if value.startswith('--symlink_prefix=') else value
        for value in result]
    environment = {MODE:INPUT_MODE,ENTRY:str(entry),DEADLINE:str(deadline),EPOCH:str(run),
        SOURCE:source_commit,GRAPH:graph_sha256,DELIVERY_REQUEST:str(run/'native-content-delivery-request.json'),
        DELIVERY_REQUEST_SHA256:request_sha256}
    index = result.index('test')+1
    result[index:index] = ['--repository_disable_download','--repo_contents_cache=',
        '--test_timeout='+str(seconds)] + ['--test_env='+key+'='+value for key,value in environment.items()]
    return result,environment


def request(args, arguments):
    if args.profile != PROFILE:
        return False
    selected(args.profile, arguments)
    allowed = {"profile", "manager", "arguments", "python", "systemd_run", "systemctl", "bazel",
        "closure", "bootstrap_closure", "zig_sdk", "java_home", "source_commit", "source_dirty",
        "state_dir", "initialize_state_dir", "coordination_dir", "become_file",
        "reuse_owned_cache", "repository_cache", "nixpkgs_source"}
    require(args.manager == "system" and type(args.reuse_owned_cache) is bool
        and not any(value for name, value in vars(args).items() if name not in allowed)
        and type(args.source_commit) is str
        and re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is not None
        and args.source_dirty == "false")
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(args.repository_cache, args.nixpkgs_source)
    return True


def command(builder, bazel, run, arguments, profile, entry, deadline, *, graph_sha256,
            dependency_lease=None, **kwargs):
    selected(profile, arguments)
    remaining(entry, deadline)
    from guard_resident_enrollment_profile import repository_inputs
    repository_inputs(kwargs.get("repository_cache"), kwargs.get("nixpkgs_source"))
    require(kwargs.get("output_base") is None and isinstance(run, Path) and run.is_absolute()
        and run.parent in kernel.resident.PUBLIC_ROOTS
        and str(run) == os.path.normpath(str(run))
        and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",run.name) is not None
        and type(kwargs.get("source_commit")) is str
        and re.fullmatch(r"[0-9a-f]{40}",kwargs["source_commit"]) is not None
        and kwargs.get("source_dirty") == "false" and type(graph_sha256) is str
        and re.fullmatch(r"[0-9a-f]{64}",graph_sha256) is not None)
    if dependency_lease is not None:
        require(type(dependency_lease) is ContentDependencyLease)
        dependency_lease.fence()
        require(not dependency_lease.capture_ready and dependency_lease.run_id == run.name and dependency_lease.state_root == run.parent
            and dependency_lease.checkout == Path.cwd().resolve(strict=True)
            and dependency_lease.source_commit == kwargs['source_commit']
            and dependency_lease.graph_sha256 == graph_sha256
            and (dependency_lease.entry,dependency_lease.deadline) == (entry,deadline))
        kwargs['output_base'] = dependency_lease.output_base
    environment = {MODE:INPUT_MODE, ENTRY:str(entry), DEADLINE:str(deadline), EPOCH:str(run),
        SOURCE:kwargs["source_commit"], GRAPH:graph_sha256}
    action_seconds = runtime_seconds(entry, deadline)
    require(action_seconds >= 1)
    result = builder(bazel, run, arguments, profile="standard", **kwargs)
    index = result.index("test") + 1
    # Repository declarations and genuine consumers bind the identical actual
    # coordinator tuple. Env presence alone never proves SDK/child readiness.
    result[index:index] = ["--repository_disable_download", "--repo_contents_cache=",
        "--test_timeout=" + str(action_seconds)] + [
        "--"+kind+"="+key+"="+value for kind in ("repo_env","test_env")
        for key,value in environment.items()]
    return result


def runtime_seconds(entry, deadline):
    return min(ACTION_SECONDS, int(remaining(entry, deadline)))


def verify_runtime(value, seconds):
    require(type(seconds) is int and 1 <= seconds <= ACTION_SECONDS)
    from yoga_delivery_settings import effective_runtime
    effective_runtime(value, seconds)


class WorkloadWitness(kernel.WorkloadWitness):
    """Only this exact new family; original kernel ownership checks unchanged."""
    def admitted_profile(self, profile):
        return profile == PROFILE


def monitor(profile, witness, readback, deadline, on_iteration, *,
            clock=time.monotonic, pause=time.sleep):
    """No routine manager reads; one terminal read still owns the exit/result fact."""
    require(profile == PROFILE and type(witness) is WorkloadWitness)
    while clock()<deadline:
        kernel.diagnostic_call("monitor-iteration", on_iteration)
        if clock()>=deadline:
            return 124
        try:
            alive=witness.alive()
        except kernel.ReservationOSError as error:
            if (type(error) is not kernel.ReservationOSError or error.reservation_phase != "worker-proc-identity"
                    or error.errno != errno.ENOENT or getattr(witness, "proc_exit_pending", False) is not True
                    or witness.bounds is None):
                raise
            try:
                return witness.confirm_proc_exit(readback, deadline, clock)
            except (kernel.ReservationOSError, kernel.ReservationValueError) as refusal:
                refusal.reservation_proc_exit = witness.proc_exit_confirmation
                raise
        if clock()>=deadline:
            return 124
        if not alive:
            actual=kernel.diagnostic_call("terminal-manager-readback", readback)
            if clock()>=deadline:
                return 124
            require(not kernel.diagnostic_call("terminal-recheck", witness.alive))
            if clock()>=deadline:
                return 124
            return witness.terminal(actual)
        left=deadline-clock()
        if left<=0:
            return 124
        pause(min(0.5,left))
    return 124


def release_worker(witness):
    """Detach new FDs before any receipt can promote success; fallback is idempotent."""
    if witness is None:
        return True
    require(type(witness) is WorkloadWitness)
    try:
        witness.close()
    except (OSError,ValueError):
        return False
    return True


def projection(entry, deadline, verified, resident):
    kernel.envelope(entry, deadline)
    require(verified is None or type(verified) is bool)
    return {"scope": "fixed-native-siwc-catalog-content-source-reserved-v1", "mode": "fresh-original-sdk-and-catalog-content-source-hub",
        "original_entry_monotonic_ns": entry, "original_deadline_monotonic_ns": deadline,
        "action_cap_seconds": ACTION_SECONDS, "verified_after_cleanup": verified, "resident": resident,
        "native_source_finalized": False, "sdk_qualified": False, "compiler_qualified": False,
        "schema_qualified": False, "package_qualified": False, "native_runtime_qualified": False,
        "native_image_qualified": False, "custody_qualified": False, "health_qualified": False,
        "credential_acquisition_qualified": False, "issuer_qualified": False,
        "timing_fit_qualified": False, "native20_qualified_by_admission": False,
        "ordinary_launch_qualified": False, "continuity_qualified": False, "live_qualified": False}
