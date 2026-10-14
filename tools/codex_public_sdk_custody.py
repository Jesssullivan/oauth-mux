"""Closed Linux public-SDK custody; never account/credential reader authority.

The maintained materialize/qualify caller owns this live domain. Foreign public
ancestry needs actual kernel readonly and mount-ID observations on BOTH held
and independently opened current names. Private proof0600 and mutable writers
still require this process's UID. No recorded/diagnostic readonly bit is used.
"""
import ctypes
import errno
import os
from pathlib import Path
import stat
import threading
from types import MappingProxyType

_SEAL = object()


def _core():
    import codex_native_sdk_carrier
    return codex_native_sdk_carrier


def need(value, reason):
    _core().need(value, "public-sdk-" + reason)


def first_cause(primary, cleanup):
    prior = BaseException.__cause__.__get__(primary)
    return cleanup if prior is None else prior


def drain(*, owners=(), fds=(), body=None):
    """Attempt every detached close once; preserve the original body cause."""
    failure = None
    for fd in fds:
        if fd is not None:
            try: os.close(fd)
            except BaseException as error:
                if failure is None: failure = error
    for owner in owners:
        if owner is not None:
            try: owner.close()
            except BaseException as error:
                if failure is None: failure = error
    if failure is not None:
        if body is not None:
            prior = BaseException.__cause__.__get__(body)
            raise body from (failure if prior is None else prior)
        raise failure


class FdSlot:
    """Preallocated receiver; an ambiguous close is attempted only once."""
    def __init__(self): self.fd = None
    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None: os.close(fd)


class _Timestamp(ctypes.Structure):
    _fields_ = (("seconds", ctypes.c_int64), ("nanoseconds", ctypes.c_uint32),
                ("reserved", ctypes.c_int32))


class _Statx(ctypes.Structure):
    # Linux UAPI statx: mnt_id is at offset144; the total ABI remains256.
    _fields_ = (("mask", ctypes.c_uint32), ("blksize", ctypes.c_uint32),
        ("attributes", ctypes.c_uint64), ("nlink", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("mode", ctypes.c_uint16), ("reserved0", ctypes.c_uint16),
        ("ino", ctypes.c_uint64), ("size", ctypes.c_uint64),
        ("blocks", ctypes.c_uint64), ("attributes_mask", ctypes.c_uint64),
        ("atime", _Timestamp), ("btime", _Timestamp),
        ("ctime", _Timestamp), ("mtime", _Timestamp),
        ("rdev_major", ctypes.c_uint32), ("rdev_minor", ctypes.c_uint32),
        ("dev_major", ctypes.c_uint32), ("dev_minor", ctypes.c_uint32),
        ("mnt_id", ctypes.c_uint64), ("reserved", ctypes.c_byte * 104))


def _mount(fd):
    """Kernel FD facts, never /proc text, pathname inference or caller records."""
    need(ctypes.sizeof(_Statx) == 256 and _Statx.mnt_id.offset == 144, "statx-ABI")
    library = ctypes.CDLL(None, use_errno=True)
    function = library.statx
    function.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                        ctypes.c_uint, ctypes.POINTER(_Statx))
    function.restype = ctypes.c_int
    result = _Statx()
    # AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW; STATX_MNT_ID is mandatory.
    if function(fd, b"", 0x1000 | 0x100, 0x1000, ctypes.byref(result)) != 0:
        number = ctypes.get_errno()
        raise OSError(number if number else errno.EIO, "SDK mount metadata unavailable")
    need(result.mask & 0x1000 != 0 and result.mnt_id > 0, "kernel-mount-id")
    filesystem = os.fstatvfs(fd)
    return result.mnt_id, filesystem.f_fsid, filesystem.f_flag


def _snapshot(fd, clock):
    clock.tick()
    before = _core().identity(os.fstat(fd))
    first = _mount(fd)
    second = _mount(fd)
    after = _core().identity(os.fstat(fd))
    clock.tick()
    need(before == after and first == second, "kernel-observation-race")
    return before, first


def _policy(info, mount, *, private=False):
    if private:
        need(info[2] == os.getuid(), "private-owner")
    elif info[2] not in (0, os.getuid()):
        need(bool(mount[2] & os.ST_RDONLY), "foreign-writable")
    need(not info[4] & 0o022 or bool(info[4] & stat.S_ISVTX), "ancestor-permissions")


class Domain:
    """Nontransferable original-clock owner; no serialized success capability."""
    def __init__(self, seal, context, clock, phase):
        import codex_retained_sdk_tree_inputs as admission
        need(type(self) is Domain and seal is _SEAL, "private-domain-constructor")
        entry, until = admission._context(context)
        need(type(clock) is _core().Clock and clock.until_ns == entry + 1170 * 10**9
            and clock.deadline == clock.until_ns / 10**9, "same-original-clock")
        need(phase in ("materialize", "qualify"), "closed-phase")
        self.phase = self.original_phase = phase
        self.clock, self.deadline, self.until_ns = clock, clock.deadline, clock.until_ns
        self.context = _core().encoded(context)
        self.pid, self.thread, self.self = os.getpid(), threading.get_ident(), self
        self.closed, self.confirmed = False, None
        self.carrier_root = self.output_parent = None
        self.carrier_pin = None
        self.proof_pins = None
        self._carrier_binding = self._output_binding = self._proof_binding = None
        self.check()

    def check(self):
        need(type(self) is Domain and self.self is self and not self.closed
            and os.getpid() == self.pid and threading.get_ident() == self.thread
            and self.phase == self.original_phase
            and self.clock.deadline == self.deadline and self.clock.until_ns == self.until_ns,
            "current-owner-clock")
        self.clock.tick()
        need((self._carrier_binding is None and self.carrier_root is None and self.carrier_pin is None)
            or self._carrier_binding == (self.carrier_root, self.carrier_pin), "same-carrier-role")
        need(self.output_parent == self._output_binding and self.proof_pins is self._proof_binding,
             "same-output-proof-roles")
        context = _core().decode(self.context)
        need(_core().encoded({name: os.environ.get("OMUX_NATIVE_SDK_TREE_" + name)
            for name in context}) == self.context, "current-context")
        if self.confirmed is not None:
            import codex_retained_sdk_tree_inputs as admission
            admission.current_creator_domain(self.confirmed, context)

    def confirm(self, raw):
        self.check()
        import codex_retained_sdk_tree_inputs as admission
        admission.current_creator_domain(raw, _core().decode(self.context))
        need(self.confirmed is None or self.confirmed == raw, "same-clock-domain")
        self.confirmed = raw
        self.check()

    def bind_carrier(self, path, pin):
        self.check()
        need(self.confirmed is not None and self.carrier_root is None, "one-carrier-role")
        self.carrier_root, self.carrier_pin = _core().absolute(path), _core().digest(pin)
        need(self.carrier_root.name == "sdk-carrier" and self.carrier_root.parent.name == "sdk-private",
             "declared-carrier-role")
        self._carrier_binding = self.carrier_root, self.carrier_pin

    def bind_output(self, path):
        self.check()
        selected = _core().absolute(path)
        need((self.confirmed is not None or self.phase == "materialize") and selected.name == "sdk-tree-public"
            and selected.parent.name == "codex_native_retained_sdk_tree_materialized"
            and (self.output_parent is None or self.output_parent == selected), "declared-output-role")
        self.output_parent = selected
        self._output_binding = selected

    def bind_proofs(self, document):
        self.check()
        import codex_native_carrier_metadata as metadata
        need(type(document) is dict and set(document) == {"kind", "proofs"}
             and document["kind"] == metadata.PROOF_KIND
             and type(document["proofs"]) is dict
             and set(document["proofs"]) == set(metadata.PROOF_ALIASES), "closed-five-proof-roles")
        selected = {}
        for role, row in document["proofs"].items():
            need(type(row) is dict and set(row) == {"path", "sha256", "alias"}
                 and row["alias"] == metadata.PROOF_ALIASES[role], "closed-proof-row")
            path = str(_core().absolute(row["path"]))
            need(path not in selected, "distinct-proof-path")
            selected[path] = _core().digest(row["sha256"])
        rows = document["proofs"]
        outer = _core().absolute(rows["outer_receipt"]["path"])
        need(outer.name == "receipt.json", "original-proof-receipt-role")
        need(rows["test_evidence"]["path"] == str(outer.parent / "test-evidence.json"), "original-proof-index-role")
        for role in ("test_log", "test_xml"):
            member = _core().absolute(rows[role]["path"])
            need(member.parent == outer.parent / "test-evidence"
                 and metadata.re.fullmatch(r"[0-9a-f]{64}[.]evidence", member.name) is not None,
                 "original-proof-log-XML-role")
        report = rows["program_report"]["path"]
        prefix = str(outer.parent / "output-base/execroot/_main/bazel-out") + "/"
        suffix = "/testlogs/tools/" + metadata.SEAL_TARGET.split(":")[1] + "/test.outputs/sdk-private/native-sdk-carrier-producer.json"
        need(report.startswith(prefix) and report.endswith(suffix)
             and metadata.re.fullmatch(r"[A-Za-z0-9_.-]+", report[len(prefix):-len(suffix)]) is not None,
             "original-proof-report-before-private-read")
        need(self.proof_pins is None or self.proof_pins == selected, "same-five-original-proofs")
        frozen = MappingProxyType(selected)
        self.proof_pins = self._proof_binding = frozen

    def root_role(self, path, owned):
        self.check()
        selected = _core().absolute(path)
        if selected == self.carrier_root:
            need(owned is False, "public-carrier-read-only")
            return "source"
        need(self.output_parent is not None, "output-role-unbound")
        suffix = selected.relative_to(self.output_parent).as_posix()
        need(suffix in (".sdk-tree-creation-private", ".sdk-tree-creation-private/tree",
            ".sdk-tree-creation-private/tree/sdk", ".sdk-tree-creation-private/tree/jdk",
            "tree", "tree/sdk", "tree/jdk"), "closed-tree-root-role")
        need(not owned or suffix in (".sdk-tree-creation-private", ".sdk-tree-creation-private/tree"),
             "closed-mutable-root-role")
        need(not owned or self.phase == "materialize", "consumer-cannot-own-creator-writes")
        return "writer" if self.phase == "materialize" else "source"

    def close(self):
        self.closed = True

    def __copy__(self): raise ValueError("public SDK domain is nontransferable")
    def __deepcopy__(self, unused): raise ValueError("public SDK domain is nontransferable")
    def __reduce_ex__(self, unused): raise ValueError("public SDK domain is nontransferable")


def materializer_domain(context, clock):
    return Domain(_SEAL, context, clock, "materialize")


def qualifier_domain(context, clock):
    return Domain(_SEAL, context, clock, "qualify")


class Directory:
    """Complete held and independent current nofollow chains, bounded depth64."""
    def __init__(self, path, domain):
        need(type(self) in (Directory, WriterDirectory, OutputDirectory, MemberDirectory)
             and type(domain) is Domain, "directory-domain-type")
        selected = self._member_path if type(self) is MemberDirectory else _core().absolute(path)
        self.path, self.domain, self.clock = selected, domain, domain.clock
        self.binding = self.path, self.domain, self.clock
        self.chain, self.pending = [], None
        try:
            domain.check()
            self.pending = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self._enroll(None)
            for name in self.path.parts[1:]:
                self.clock.tick()
                parent = self.fd
                before = _core().identity(os.stat(name, dir_fd=parent, follow_symlinks=False))
                need(stat.S_ISDIR(before[4]), "directory-type")
                self.pending = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=parent)
                self._enroll(name, before, parent)
            self.check()
        except BaseException as body:
            try: self.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise

    @property
    def fd(self): return self.chain[-1][1]

    def _selected(self, info, mount):
        # Writers may change their OWN writable parent timestamps. Immutable
        # public ancestry always retains full nine, including foreign RO nodes.
        if type(self) in (WriterDirectory, OutputDirectory) and info[2] in (0, os.getuid()) and not mount[2] & os.ST_RDONLY:
            return info[:5]
        return info

    def _enroll(self, name, before=None, parent=None):
        info, mount = _snapshot(self.pending, self.clock)
        need(stat.S_ISDIR(info[4]), "directory-held-type")
        _policy(info, mount)
        if before is not None:
            need(before == info == _core().identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 "directory-open-race")
        self.chain.append((name, self.pending, self._selected(info, mount), mount))
        self.pending = None

    def check(self):
        self.domain.check()
        need(bool(self.chain) and self.pending is None and self.binding == (self.path, self.domain, self.clock),
             "directory-active")
        current = pending = None
        primary = None
        try:
            for index, (name, held, selected, original_mount) in enumerate(self.chain):
                self.clock.tick()
                if index == 0:
                    pending = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    before = None
                else:
                    before = _core().identity(os.stat(name, dir_fd=current, follow_symlinks=False))
                    pending = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=current)
                live, live_mount = _snapshot(pending, self.clock)
                old, old_mount = _snapshot(held, self.clock)
                _policy(live, live_mount); _policy(old, old_mount)
                need(live == old, "current-held-full-nine")
                need(self._selected(live, live_mount) == selected == self._selected(old, old_mount)
                    and live_mount == original_mount == old_mount, "current-mount-and-ancestor")
                if index:
                    after = _core().identity(os.stat(name, dir_fd=current, follow_symlinks=False))
                    need(before == live == after, "current-named-chain-race")
                retired, current, pending = current, pending, None
                if retired is not None: os.close(retired)
            self.domain.check()
        except BaseException as body:
            primary = body
            raise
        finally:
            failure = None
            for fd in (pending, current):
                if fd is not None:
                    try: os.close(fd)
                    except BaseException as error:
                        if failure is None: failure = error
            if failure is not None:
                if primary is not None: raise primary from first_cause(primary, failure)
                raise failure

    def observe(self, name, held, expected, *, private=False):
        """Never use old-parent stat alone as CURRENT named mount authority."""
        self.check()
        current = self.fresh()
        fd = None
        primary = None
        try:
            before = _core().identity(os.stat(name, dir_fd=current.fd, follow_symlinks=False))
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if stat.S_ISDIR(before[4]): flags |= os.O_DIRECTORY
            need(stat.S_ISDIR(before[4]) or stat.S_ISREG(before[4]), "observed-node-kind")
            fd = os.open(name, flags, dir_fd=current.fd)
            live, mount = _snapshot(fd, self.clock)
            old, old_mount = _snapshot(held, self.clock)
            _policy(live, mount, private=private); _policy(old, old_mount, private=private)
            need(before == live == old == expected == _core().identity(
                os.stat(name, dir_fd=current.fd, follow_symlinks=False)), "observed-current-node")
            need(mount == old_mount, "observed-current-mount")
            current.check(); self.check()
        except BaseException as body:
            primary = body
            raise
        finally:
            failure = None
            if fd is not None:
                try: os.close(fd)
                except BaseException as error: failure = error
            try: current.close()
            except BaseException as error:
                if failure is None: failure = error
            if failure is not None:
                if primary is not None: raise primary from first_cause(primary, failure)
                raise failure

    def fresh(self): return type(self)(self.path, self.domain)

    def close(self):
        entries, self.chain = self.chain, []
        pending, self.pending = self.pending, None
        failure = None
        for unused, fd, selected, mount in reversed(entries):
            if fd == pending: pending = None
            try: os.close(fd)
            except BaseException as error:
                if failure is None: failure = error
        if pending is not None:
            try: os.close(pending)
            except BaseException as error:
                if failure is None: failure = error
        if failure is not None: raise failure


class WriterDirectory(Directory):
    """Public ancestry permits no foreign writable node; endpoint stays owned."""
    def __init__(self, path, domain):
        super().__init__(path, domain)
        try:
            info = os.fstat(self.fd)
            need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) in (0o700, 0o755),
                 "owned-writer-endpoint")
        except BaseException as body:
            try: self.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise


class OutputDirectory(Directory):
    """Creator-owned mutable ancestry below the fixed declared output parent."""
    def __init__(self, path, domain):
        domain.root_role(path, False)
        super().__init__(path, domain)
        try:
            info = os.fstat(self.fd)
            need(domain.phase == "materialize" and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o700, 0o555), "owned-output-endpoint")
        except BaseException as body:
            try: self.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise


class MemberDirectory(Directory):
    """A root<=64 plus member<=64, preserving the old two separate bounds.

    Generic Directory still accepts only the existing absolute depth64. This
    exact variant is internal to an actual PublicRoot; no arbitrary extended
    path or caller depth flag is admitted.
    """
    def __init__(self, root, name):
        need(type(self) is MemberDirectory and type(root) is _core().PublicRoot, "member-exact-root")
        root.check()
        _core().absolute(root.path)
        parts = _core().relative(name, empty=True)
        self.member_root, self.member_name = root, name
        self._member_path = root.path.joinpath(*parts)
        need(len(self._member_path.parts) - 1 <= 2 * _core().MAX_DEPTH, "member-combined-bound")
        super().__init__(self._member_path, root.domain)

    def fresh(self): return MemberDirectory(self.member_root, self.member_name)


class Leaf:
    """Owned complete byte reader with live alias, parent and mount witnesses."""
    def __init__(self, alias, domain, maximum, pin=None, role="control"):
        need(type(self) is Leaf and type(domain) is Domain and role in ("control", "proof"), "leaf-type-role")
        need(type(maximum) is int and 0 < maximum <= _core().MAX_METADATA, "leaf-bound")
        if pin is not None: _core().digest(pin)
        need(role != "proof" or pin is not None, "proof-before-read-pin")
        self.alias, self.domain, self.clock = _core().absolute(alias), domain, domain.clock
        self.maximum, self.pin, self.role = maximum, pin, role
        self.parent = self.alias_parent = self.fd = None
        self.closed = False
        try:
            self.path = self.alias.resolve(strict=True)
            if role == "proof":
                need(domain.proof_pins is not None and domain.proof_pins.get(str(self.path)) == pin,
                     "only-five-declared-original-proofs")
            self.alias_parent = Directory(self.alias.parent.resolve(strict=True), domain)
            info = os.stat(self.alias.name, dir_fd=self.alias_parent.fd, follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), "leaf-alias-kind")
            self.alias_witness = _core().identity(info)
            self.literal = os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) if stat.S_ISLNK(info.st_mode) else None
            self.parent = Directory(self.path.parent, domain)
            info = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
            modes = (0o444, 0o555, 0o600) if role == "proof" else (0o444, 0o555, 0o644)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) in modes
                 and 0 < info.st_size <= maximum, "leaf-custody")
            if role == "proof": need(info.st_uid == os.getuid(), "original-proof-process-owner")
            self.witness = _core().identity(info)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                              dir_fd=self.parent.fd)
            self.raw = self.read()
        except BaseException as body:
            try: self.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise

    def check(self):
        self.domain.check()
        need(not self.closed and self.fd is not None and self.alias.resolve(strict=True) == self.path,
             "leaf-current-alias")
        self.alias_parent.check(); self.parent.check()
        need(self.alias.parent.resolve(strict=True) == self.alias_parent.path
            and self.alias_witness == _core().identity(os.stat(self.alias.name,
                dir_fd=self.alias_parent.fd, follow_symlinks=False))
            and (self.literal is None or os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) == self.literal),
            "leaf-original-alias")
        self.parent.observe(self.path.name, self.fd, self.witness, private=self.role == "proof")

    def read(self):
        self.check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        raw, count = bytearray(), 0
        while True:
            self.clock.tick()
            block = os.read(self.fd, min(65536, self.maximum + 1 - count))
            self.clock.tick()
            if not block: break
            count += len(block)
            need(count <= self.maximum and count <= self.witness[6], "leaf-complete-bound")
            raw.extend(block)
        self.check()
        need(count == self.witness[6], "leaf-complete-EOF")
        result = bytes(raw)
        if self.pin is not None: need(_core().sha(result) == self.pin, "leaf-complete-sha")
        return result

    def close(self):
        self.closed = True
        fd, self.fd = self.fd, None
        parent, self.parent = self.parent, None
        alias, self.alias_parent = self.alias_parent, None
        failure = None
        if fd is not None:
            try: os.close(fd)
            except BaseException as error: failure = error
        for owner in (parent, alias):
            if owner is not None:
                try: owner.close()
                except BaseException as error:
                    if failure is None: failure = error
        if failure is not None: raise failure


def read(path, domain, maximum, pin=None, role="control"):
    owner = Leaf(path, domain, maximum, pin, role)
    try: return owner.raw
    except BaseException as body:
        try: owner.close()
        except BaseException as cleanup: raise body from first_cause(body, cleanup)
        raise
    finally: owner.close()


class Controls:
    """At most32 current controls and exactly five original declared proof roles."""
    def __init__(self, domain):
        need(type(self) is Controls and type(domain) is Domain, "controls-type")
        self.domain, self.held, self.raws, self.aliases = domain, {}, {}, []
        self.closed = False

    def add(self, alias, pin=None, maximum=64 * 1024 * 1024, role="control"):
        self.domain.check()
        need(not self.closed and len(self.held) < 32, "controls-bound")
        owner = Leaf(alias, self.domain, maximum, pin, role)
        try:
            key = str(owner.path)
            if key in self.held:
                need(self.raws[key] == owner.raw and self.held[key].witness == owner.witness,
                     "same-held-control")
                owner.close()
            else:
                self.held[key] = owner
                self.raws[key] = owner.raw
        except BaseException as body:
            try: owner.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise
        self.fence()
        return self.raws[key]

    def add_alias(self, alias, physical):
        self.domain.check()
        need(not self.closed and len(self.aliases) < 64, "alias-bound")
        alias = _core().absolute(alias)
        need(alias.resolve(strict=True) == physical, "declared-alias-target")
        owner = Directory(alias.parent.resolve(strict=True), self.domain)
        try:
            info = os.stat(alias.name, dir_fd=owner.fd, follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), "declared-alias-kind")
            literal = os.readlink(alias.name, dir_fd=owner.fd) if stat.S_ISLNK(info.st_mode) else None
            self.aliases.append((alias, physical, owner, _core().identity(info), literal))
        except BaseException as body:
            try: owner.close()
            except BaseException as cleanup: raise body from first_cause(body, cleanup)
            raise
        self.fence()

    def carrier_proofs(self, selected, proofs, deadline):
        import codex_native_carrier_metadata as metadata
        protocol = metadata.protocol
        need(type(proofs) is metadata.PublicProofInputs and proofs.domain is self.domain
             and deadline == self.domain.deadline and metadata._SCOPE.get() == deadline,
             "exact-original-proof-owner")
        proofs.recheck(deadline)
        captured = {}
        def capture(role, path, pin):
            row = proofs.document["proofs"][role]
            need(row == {"path": str(path), "sha256": pin, "alias": metadata.PROOF_ALIASES[role]},
                 "declared-original-proof-row")
            aliases = [alias for alias, physical in proofs.aliases if physical == path]
            need(len(aliases) == 1, "one-original-proof-alias")
            proofs.join(role, path, pin, deadline)
            captured[role] = self.add(aliases[0], pin, 64 * 1024 * 1024, "proof")
            proofs.join(role, path, pin, deadline)
        producer = selected["qualification"]["producer"]
        protocol.producer_pin(producer)
        outer_path = protocol.path(producer["receipt"])
        capture("outer_receipt", outer_path, producer["sha256"])
        outer = _core().decode(captured["outer_receipt"])
        capture("test_evidence", outer_path.parent / "test-evidence.json", outer["test_evidence"]["sha256"])
        index = _core().decode(captured["test_evidence"])
        need(type(index["schema"]) is int and index["schema"] == 1 and index["targets"] == [metadata.SEAL_TARGET]
            and type(index["results"]) is list and len(index["results"]) == 1
            and index["results"][0]["target"] == metadata.SEAL_TARGET
            and index["results"][0]["state"] == "observed", "original-proof-evidence-index")
        for role, original in (("test_log", "test.log"), ("test_xml", "test.xml")):
            entries = [row for row in index["results"][0]["files"] if row["source"] == original]
            need(len(entries) == 1 and entries[0]["state"] == "copied", "one-copied-original-proof")
            row = entries[0]
            need(metadata.re.fullmatch(r"[0-9a-f]{64}[.]evidence", row["file"]) is not None,
                 "original-proof-leaf-name")
            capture(role, outer_path.parent / "test-evidence" / row["file"], row["sha256"])
            need(type(row["bytes"]) is int and row["bytes"] == len(captured[role]), "original-proof-complete-bytes")
        report = selected["qualification"]["report"]
        capture("program_report", protocol.path(report["path"]), report["sha256"])
        proofs.recheck(deadline); self.fence()
        return captured

    def fence(self):
        self.domain.check()
        need(not self.closed, "controls-active")
        for owner in self.held.values(): owner.check()
        for alias, physical, owner, witness, literal in self.aliases:
            owner.check()
            need(alias.resolve(strict=True) == physical and alias.parent.resolve(strict=True) == owner.path
                 and _core().identity(os.stat(alias.name, dir_fd=owner.fd, follow_symlinks=False)) == witness
                 and (literal is None or os.readlink(alias.name, dir_fd=owner.fd) == literal), "original-control-alias")
        self.domain.check()

    def full(self):
        self.fence()
        for path, owner in self.held.items(): need(owner.read() == self.raws[path], "held-controls-full-readback")
        self.fence()

    def close(self):
        self.closed = True
        held, self.held = self.held, {}
        aliases, self.aliases = self.aliases, []
        failure = None
        for owner in held.values():
            try: owner.close()
            except BaseException as error:
                if failure is None: failure = error
        for row in aliases:
            try: row[2].close()
            except BaseException as error:
                if failure is None: failure = error
        if failure is not None: raise failure
