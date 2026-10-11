"""One declared logical Python role and its retained physical interpreter.

This is generation-specific inode/byte custody, never basename acceptance or
an application/native-peer authentication capability.
"""
import hashlib
import os
from pathlib import Path
import stat
import time

ROOT = '/nix/store/0r6k8xa2kgqyp3r4v2w7yrb80ma2iawm-python3-3.13.12'
LOGICAL = ROOT+'/bin/python3'
PHYSICAL = ROOT+'/bin/python3.13'
MAXIMUM = 64*1024**2


def require(value):
    if value is not True:
        raise ValueError('declared-python-role-refused')


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class RoleIdentity:
    def __init__(self, physical, native, deadline):
        self.chain, self.fds = [], []
        self.physical, self.logical, self.deadline = physical, LOGICAL, deadline
        require(physical == PHYSICAL and type(native) is dict
            and native.get('packages', {}).get('python', {}).get('out') == ROOT)
        try:
            current = Path('/')
            fd = os.open(current, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.chain.append((current, fd, identity(os.fstat(fd))[:5]))
            for part in Path(ROOT+'/bin').parts[1:]:
                self.tick(); current /= part
                fd = os.open(part, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                    dir_fd=self.chain[-1][1])
                info = os.fstat(fd)
                self.chain.append((current, fd, identity(info)[:5]))
            for path, fd, _ in self.chain:
                info = os.fstat(fd)
                require(info.st_uid == 0 and (not info.st_mode & 0o022 or
                    path == Path('/nix/store') and stat.S_IMODE(info.st_mode) == 0o1775))
                if path.is_relative_to(ROOT):
                    require(not info.st_mode & 0o222)
            self.link = identity(os.stat('python3', dir_fd=fd, follow_symlinks=False))
            require(stat.S_ISLNK(self.link[2]) and self.link[3] == 0
                and os.readlink('python3', dir_fd=fd) == 'python3.13')
            self.fds.append(os.open('python3.13', os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,
                dir_fd=fd))
            self.saved = identity(os.fstat(self.fds[0]))
            require(stat.S_ISREG(self.saved[2]) and self.saved[3] == 0
                and not self.saved[2] & 0o222 and bool(self.saved[2] & 0o111)
                and 0 < self.saved[6] <= MAXIMUM)
            # The literal single-hop alias is the only followed link. Before
            # reading, require its actual opened inode to be the held physical one.
            self.fds.append(os.open('python3', os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=fd))
            require(identity(os.fstat(self.fds[1])) == self.saved)
            self.digest = self.hash(self.fds[0])
            self.check()
        except BaseException:
            self.close()
            raise

    def tick(self):
        require(type(self.deadline) is int and 0 < self.deadline-time.monotonic_ns() <= 1200*10**9)

    def anchored(self):
        self.tick(); require(len(self.fds) == 2)
        for index, (path, fd, saved) in enumerate(self.chain):
            named = path.stat(follow_symlinks=False) if index == 0 else os.stat(path.name,
                dir_fd=self.chain[index-1][1], follow_symlinks=False)
            require(saved == identity(os.fstat(fd))[:5] == identity(named)[:5])
        directory = self.chain[-1][1]
        require(self.link == identity(os.stat('python3', dir_fd=directory, follow_symlinks=False))
            and os.readlink('python3', dir_fd=directory) == 'python3.13')
        require(self.saved == identity(os.stat('python3.13', dir_fd=directory, follow_symlinks=False)))
        for fd in self.fds:
            require(identity(os.fstat(fd)) == self.saved)

    def hash(self, fd):
        digest, total = hashlib.sha256(), 0
        while total <= MAXIMUM:
            self.tick()
            data = os.pread(fd, min(65536, MAXIMUM+1-total), total)
            if not data:
                break
            total += len(data); digest.update(data)
        require(total == self.saved[6] and total <= MAXIMUM)
        return digest.hexdigest()

    def check(self):
        self.anchored()
        require(all(self.hash(fd) == self.digest for fd in self.fds))
        self.anchored()

    def logical_tools(self, physical_tools):
        self.check()
        require(type(physical_tools) is dict and physical_tools.get('python') == self.physical)
        return dict(physical_tools, python=self.logical)

    def close(self):
        held = list(reversed(self.fds)) + [row[1] for row in reversed(self.chain)]
        self.fds, self.chain = [], []
        failed = False
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                failed = True
        require(not failed)
