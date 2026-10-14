"""Original private module creators, byte admission and bounded once retirement."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat

import home_manager_realization_inputs as inputs


class Slot:
    __slots__ = ("fd", "witness", "initial")
    def __init__(self):
        self.fd = self.witness = self.initial = None


class Reader:
    __slots__ = ("fd", "offset", "deadline")
    def __init__(self, fd, deadline):
        self.fd, self.offset, self.deadline = fd, 0, deadline
    def read(self, count):
        inputs.require(type(count) is int and 0 <= count <= 65536)
        inputs.private.tick(self.deadline)
        raw = os.pread(self.fd, count, self.offset)
        self.offset += len(raw)
        inputs.private.tick(self.deadline)
        return raw


class Modules:
    def __init__(self, parent, modules):
        inputs.require(type(modules) is dict and set(modules) == set(inputs.MODULES) | {"home-manager-generation.nix"})
        self.parent = parent
        self.path = parent.path / "generation-modules"
        self.modules = modules
        self.names = tuple(modules)
        # All owner records and retirement inventory precede every acquisition.
        self.root = Slot()
        self.writers = {name: Slot() for name in self.names}
        self.readers = {name: Slot() for name in self.names}
        self.retirement = [*self.writers.values(), *self.readers.values(), self.root]
        self.root_born = None

    def create(self, deadline):
        failure = None
        try:
            self.parent.recheck(); inputs.private.tick(deadline)
            self.path.mkdir(mode=0o700)
            self.root_born = inputs.facts(self.path.lstat())
            self.root.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            actual = inputs.facts(os.fstat(self.root.fd))
            inputs.require(actual == self.root_born and actual[2] == os.getuid()
                and stat.S_ISDIR(actual[4]) and stat.S_IMODE(actual[4]) == 0o700)
            for name in self.names:
                raw = self.modules[name]
                inputs.require(type(raw) is bytes and 0 < len(raw) <= 1024**2)
                writer, reader = self.writers[name], self.readers[name]
                writer.fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=self.root.fd)
                writer.initial = inputs.facts(os.fstat(writer.fd))
                inputs.require(stat.S_ISREG(writer.initial[4]) and writer.initial[2] == os.getuid()
                    and writer.initial[5] == 1 and writer.initial[6] == 0 and stat.S_IMODE(writer.initial[4]) == 0o600)
                offset = 0
                while offset < len(raw):
                    inputs.private.tick(deadline)
                    count = os.write(writer.fd, raw[offset:]); inputs.require(count > 0); offset += count
                os.fchmod(writer.fd, 0o444); os.fsync(writer.fd)
                writer.witness = inputs.facts(os.fstat(writer.fd))
                inputs.require(writer.witness[:4] == writer.initial[:4] and writer.witness[5] == 1
                    and writer.witness[6] == len(raw) and stat.S_IMODE(writer.witness[4]) == 0o444
                    and writer.witness == inputs.facts(os.stat(name, dir_fd=self.root.fd, follow_symlinks=False)))
                reader.fd = os.dup(writer.fd)
                reader.witness = writer.witness
                inputs.require(reader.fd != writer.fd and inputs.facts(os.fstat(reader.fd)) == reader.witness)
            os.fchmod(self.root.fd, 0o555); os.fsync(self.root.fd)
            self.root.witness = inputs.facts(os.fstat(self.root.fd))
            inputs.require(self.root.witness[:4] == self.root_born[:4]
                and self.root.witness == inputs.facts(self.path.lstat())
                and stat.S_IMODE(self.root.witness[4]) == 0o555)
            self.admit(deadline)
            # Close original writers only after their duplicate readback owners
            # pin the same creators. Close-time mutations cannot be rebased.
            for name in self.names:
                writer = self.writers[name]
                closing, writer.fd = writer.fd, None
                os.close(closing)
            self.admit(deadline)
        except BaseException as error:
            failure = error
            try: self.close(deadline, check=False)
            except BaseException as cleanup: raise failure from cleanup
            raise

    def fence(self):
        self.parent.recheck()
        inputs.require(self.root.witness is not None and self.root.witness == inputs.facts(self.path.lstat()))
        if self.root.fd is not None:
            inputs.require(inputs.facts(os.fstat(self.root.fd)) == self.root.witness
                and set(os.listdir(self.root.fd)) == set(self.names))
        for name in self.names:
            reader = self.readers[name]
            inputs.require(reader.witness is not None and reader.witness == inputs.facts((self.path/name).lstat()))
            if reader.fd is not None: inputs.require(inputs.facts(os.fstat(reader.fd)) == reader.witness)

    def admit(self, deadline):
        self.fence()
        for name in self.names:
            reader = self.readers[name]
            inputs.require(reader.fd is not None)
            stream = Reader(reader.fd, deadline)
            chunks, total = [], 0
            while True:
                block = stream.read(65536)
                if not block: break
                total += len(block); inputs.require(total <= len(self.modules[name])); chunks.append(block)
            inputs.require(total == len(self.modules[name]) and b"".join(chunks) == self.modules[name])
            self.fence()
        inputs.private.tick(deadline)

    @contextmanager
    def open(self, unused_root, name, deadline):
        inputs.require(name in self.readers and self.readers[name].fd is not None)
        self.fence()
        yield Reader(self.readers[name].fd, deadline)
        self.fence(); inputs.private.tick(deadline)

    def close(self, deadline, *, check=True):
        primary = None
        if check and self.root.witness is not None:
            try: self.fence(); inputs.private.tick(deadline)
            except BaseException as error: primary = error
        # Preallocated inventory; every original handle is detached first and
        # attempted once. An ambiguous close is never retried.
        for slot in self.retirement:
            closing, slot.fd = slot.fd, None
            if closing is not None:
                try: os.close(closing)
                except BaseException as error:
                    if primary is None: primary = error
        if check and self.root.witness is not None:
            try: self.fence(); inputs.private.tick(deadline)
            except BaseException as error:
                if primary is None: primary = error
        if primary is not None: raise primary
