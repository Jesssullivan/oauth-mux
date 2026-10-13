"""Whole PUBLIC packages, independent producer bytes and fresh local custody.

Content retention never restores an old physical witness or installed capability.
Only observe-custody-existing consumes qualified retention in this version.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
import pack

KIND = "omux-public-package-retention-v1"
FILES = ("archive.tar.gz", "release-manifest.json", "producer-receipt.json", "descriptor.json")
MAX_DESCRIPTOR = 2 * 1024 * 1024
MAX_QUALIFICATION = 8 * 1024 * 1024


def require(value):
    if value is not True: raise ValueError("public-package-retention-refused")


def cleanup_cause(error, cleanup):
    prior = BaseException.__cause__.__get__(error)
    raise BaseException.with_traceback(error, BaseException.__traceback__.__get__(error)) from (cleanup if prior is None else prior)


def tick(until):
    require(type(until) is int and time.monotonic_ns() < until)


def canonical(path):
    path = Path(path)
    require(path.is_absolute() and path != Path("/") and str(path) == os.path.normpath(str(path))
            and ".." not in path.parts and len(path.parts) <= 64
            and all(not any(ord(c) < 32 or ord(c) == 127 for c in part) for part in path.parts))
    return path


def stable(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def full(info):
    return stable(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def decode(raw):
    def unique(items):
        value = {}
        for key, item in items:
            require(key not in value); value[key] = item
        return value
    def invalid(unused): raise ValueError("public-package-retention-refused")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


class Directory:
    """Every nofollow ancestor stays enrolled; selected sealed root is full9."""
    def __init__(self, path, until, *, create=False, sealed=False, private=True):
        self.path, self.until = canonical(path), until
        self.chain, self.pending, self.closed = [], None, False
        self.sealed, self.anchor = sealed, None
        try:
            self.pending = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.chain.append((None, self.pending, stable(os.fstat(self.pending))))
            self.pending = None
            for name in self.path.parts[1:]:
                tick(until); parent = self.chain[-1][1]
                if create:
                    try: os.mkdir(name, 0o700, dir_fd=parent)
                    except FileExistsError: pass
                before = os.stat(name, dir_fd=parent, follow_symlinks=False)
                require(stat.S_ISDIR(before.st_mode) and before.st_uid in (0, os.getuid())
                        and (not before.st_mode & 0o022 or before.st_uid == 0 and bool(before.st_mode & stat.S_ISVTX)))
                self.pending = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                held = os.fstat(self.pending)
                require(stable(before) == stable(held) == stable(os.stat(name, dir_fd=parent, follow_symlinks=False)))
                self.chain.append((name, self.pending, stable(held))); self.pending = None
            info = os.fstat(self.fd)
            require(info.st_uid in (0, os.getuid()) and (not private or info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == (0o555 if sealed else 0o700)))
            self.anchor = full(info) if sealed else stable(info)
            self.recheck()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: cleanup_cause(error,cleanup)
            raise

    @property
    def fd(self): return self.chain[-1][1]

    def recheck(self):
        tick(self.until); require(not self.closed)
        for index, (name, fd, witness) in enumerate(self.chain):
            require(stable(os.fstat(fd)) == witness)
            if index: require(stable(os.stat(name, dir_fd=self.chain[index-1][1], follow_symlinks=False)) == witness)
        last = full if self.sealed else stable
        require(last(os.fstat(self.fd)) == self.anchor
                == last(os.stat(self.path.name, dir_fd=self.chain[-2][1], follow_symlinks=False)))
        tick(self.until)

    def close(self):
        self.closed = True; pending, self.pending = self.pending, None; first = None
        if pending is not None:
            for unused, fd, unused_stamp in self.chain:
                if fd == pending: pending = None; break
        while self.chain:
            unused, fd, unused_stamp = self.chain.pop()
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if pending is not None:
            try: os.close(pending)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


class File:
    """Own one exact named/held regular file; no alias or hardlink admission."""
    def __init__(self, parent, name, maximum, *, mode=None, owned=True):
        self.parent, self.path, self.fd = parent, parent.path/name, None
        self.anchor, self.raw = None, None
        try:
            parent.recheck()
            before = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            require(type(owned) is bool and stat.S_ISREG(before.st_mode)
                    and before.st_uid in ((os.getuid(),) if owned else (0,os.getuid())) and before.st_nlink == 1
                    and not before.st_mode & 0o022 and 0 <= before.st_size <= maximum
                    and (mode is None or stat.S_IMODE(before.st_mode) == mode))
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent.fd)
            self.anchor = full(before)
            require(full(os.fstat(self.fd)) == self.anchor)
            chunks, total = [], 0
            while True:
                tick(parent.until); block = os.read(self.fd, min(65536, maximum-total+1))
                if not block: break
                total += len(block); require(total <= maximum); chunks.append(block)
            self.raw = b"".join(chunks); require(len(self.raw) == before.st_size)
            self.recheck()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: cleanup_cause(error,cleanup)
            raise

    def recheck(self):
        self.parent.recheck(); require(self.fd is not None)
        require(full(os.fstat(self.fd)) == self.anchor == full(os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)))
        tick(self.parent.until)

    def close(self):
        fd, self.fd = self.fd, None
        if fd is not None: os.close(fd)


class Owners:
    """Enroll actual owners before later allocation; detach and attempt all once."""
    def __init__(self): self.values, self.pending = [], None
    def add(self, owner):
        self.pending = owner
        self.values.append(owner); self.pending = None
        return owner
    def close(self):
        pending, self.pending = self.pending, None; first = None
        if pending is not None:
            for owner in self.values:
                if owner is pending: pending = None; break
        while self.values:
            owner = self.values.pop()
            try: owner.close()
            except BaseException as error:
                if first is None: first = error
        if pending is not None:
            try: pending.close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


def facts(payload):
    manifest, files = pack.verify_bundle(payload)
    require(decode(files["release-manifest.json"]) == manifest)
    unused, modes = pack.archive_contents(payload)
    members = {name:{"sha256":sha(raw), "bytes":len(raw), "mode":modes[name]} for name,raw in sorted(files.items())}
    return manifest, files["release-manifest.json"], members


def descriptor(payload, original, qualification_raw):
    manifest, raw, members = facts(payload)
    return {"schema_version":1, "kind":KIND, "original":original,
        "archive_sha256":sha(payload), "archive_bytes":len(payload),
        "manifest_sha256":sha(raw), "manifest_bytes":len(raw), "members":members,
        "artifact":{"channel":manifest.get("channel", "unknown"), "target":manifest["target"],
            "distribution":manifest["distribution"], "provenance":manifest["provenance"]},
        "producer_receipt_sha256":sha(qualification_raw), "producer_receipt_bytes":len(qualification_raw),
        "producer_qualified":original is not None, "installed_image_qualified":False,
        "native_runtime_qualified":False, "old_physical_witness_restored":False}


def location(records, archive_pin, qualifier_pin):
    require(re.fullmatch(r"[0-9a-f]{64}",archive_pin) is not None
            and (qualifier_pin == "unqualified" or re.fullmatch(r"[0-9a-f]{64}",qualifier_pin) is not None))
    return canonical(records)/"public-packages"/archive_pin/qualifier_pin


def retention_pin(value, records, selection):
    require(type(value) is dict and set(value) == {"path","sha256","bytes"}
        and type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",value["sha256"]) is not None
        and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_DESCRIPTOR)
    root = location(records, selection["archive_sha256"], selection["qualification"]["sha256"])
    require(canonical(value["path"]) == root/"descriptor.json"
            and canonical(selection["archive_path"]) == root/"archive.tar.gz")
    return root


class HeldPackage:
    """Fresh current content/namespace owner, never a persisted physical proof."""
    def __init__(self, root, until, *, expected=None):
        self.owners, self.pending, self.closed = Owners(), None, False
        self.root = self.archive = self.qualification = self.manifest = self.control = None
        try:
            self.root = self.owners.add(Directory(root, until, sealed=True))
            require(set(os.listdir(self.root.fd)) == set(FILES))
            self.archive = self.owners.add(File(self.root, FILES[0], pack.MAX_BYTES, mode=0o444))
            self.manifest = self.owners.add(File(self.root, FILES[1], pack.MAX_BYTES, mode=0o444))
            self.qualification = self.owners.add(File(self.root, FILES[2], MAX_QUALIFICATION, mode=0o444))
            self.control = self.owners.add(File(self.root, FILES[3], MAX_DESCRIPTOR, mode=0o444))
            self.document = decode(self.control.raw)
            require(encoded(self.document) == self.control.raw and (expected is None or self.control.raw == encoded(expected)))
            original = self.document["original"]
            require(self.document == descriptor(self.archive.raw, original, self.qualification.raw))
            require(self.manifest.raw == facts(self.archive.raw)[1])
            self.recheck()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: cleanup_cause(error,cleanup)
            raise

    def recheck(self):
        require(not self.closed); self.root.recheck()
        require(set(os.listdir(self.root.fd)) == set(FILES))
        for owner in (self.archive,self.manifest,self.qualification,self.control): owner.recheck()
        self.root.recheck()

    def full(self):
        self.recheck()
        for owner in (self.archive,self.manifest,self.qualification,self.control):
            tick(self.root.until); os.lseek(owner.fd,0,os.SEEK_SET); h=hashlib.sha256(); total=0
            while True:
                tick(self.root.until); block=os.read(owner.fd,65536)
                if not block: break
                total+=len(block); require(total <= len(owner.raw)); h.update(block)
            require(total == len(owner.raw) and h.hexdigest() == sha(owner.raw)); owner.recheck()
        self.recheck()

    def reference(self):
        self.recheck()
        return {"path":str(self.control.path),"sha256":sha(self.control.raw),"bytes":len(self.control.raw)}

    def close(self):
        self.closed = True; self.owners.close()


class Source:
    """Actual current producer/archive owner; no caller dictionary proves source."""
    def __init__(self, path, until, *, original=None, home=None):
        self.owners, self.original, self.closed = Owners(), original, False
        self.until = until
        self.original_raw = encoded(original)
        self.archive = self.qualification = None
        try:
            if original is not None:
                import guard_resident_owned_update as owned
                owned.start_pins(original, home)
                require(Path(path) == Path(original["archive_path"]))
                parent=self.owners.add(Directory(Path(original["qualification"]["path"]).parent,until,private=False))
                self.qualification=self.owners.add(File(parent,"receipt.json",MAX_QUALIFICATION,owned=False))
                q=original["qualification"]
                require(len(self.qualification.raw) == q["bytes"] and sha(self.qualification.raw) == q["sha256"])
                output=owned.qualification_output(decode(self.qualification.raw),q)
                require(Path(path) == output/owned.ARCHIVE_RELATIVE)
            parent=self.owners.add(Directory(canonical(path).parent,until,private=False))
            self.archive=self.owners.add(File(parent,Path(path).name,pack.MAX_BYTES,owned=False))
            manifest,raw,unused=facts(self.archive.raw)
            if original is not None:
                require(len(self.archive.raw) == original["archive_bytes"] and sha(self.archive.raw) == original["archive_sha256"]
                    and sha(raw) == original["manifest_sha256"] and manifest["channel"] == "release"
                    and manifest["distribution"] == "portable-linux" and manifest["target"] == "x86_64-linux")
            self.recheck()
        except BaseException as error:
            try:self.close()
            except BaseException as cleanup:cleanup_cause(error,cleanup)
            raise
    def recheck(self):
        require(not self.closed and encoded(self.original) == self.original_raw)
        for owner in self.owners.values:owner.recheck()
    def close(self):self.closed=True;self.owners.close()


def publish(source, records, until):
    """Retain exactly current verified PUBLIC bytes; never overwrite a package."""
    require(type(source) is Source and not source.closed and source.until == until)
    source.recheck();tick(until)
    payload=source.archive.raw
    qualification_raw=b"null\n" if source.qualification is None else source.qualification.raw
    original=source.original
    document=descriptor(payload,original,qualification_raw);raw=encoded(document)
    require(len(raw) <= MAX_DESCRIPTOR)
    qualifier="unqualified" if original is None else original["qualification"]["sha256"]
    root=location(records,sha(payload),qualifier)
    parent=Directory(root.parent,until,create=True)
    directory=fd=None;failure=None;reference=None;writers=[]
    try:
        try:os.mkdir(root.name,0o700,dir_fd=parent.fd)
        except FileExistsError:
            held=HeldPackage(root,until,expected=document)
            error=None
            try:held.full();source.recheck();held.recheck();reference=held.reference()
            except BaseException as body:error=body;raise
            finally:
                try:held.close()
                except BaseException as cleanup:
                    if error is not None:cleanup_cause(error,cleanup)
                    raise
        else:
            # Exclusive final directory is an unqualified partial object until
            # all exact leaves, descriptor-last and readonly sealing complete.
            # Interruptions preserve it for explicit owned retirement; never
            # erase a competing/modified object or touch the installed image.
            directory=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
            created=stable(os.fstat(directory))
            require(created == stable(os.stat(root.name,dir_fd=parent.fd,follow_symlinks=False)))
            for name,content in zip(FILES,(payload,facts(payload)[1],qualification_raw,raw)):
                tick(until);parent.recheck()
                require(stable(os.fstat(directory)) == created == stable(os.stat(root.name,dir_fd=parent.fd,follow_symlinks=False)))
                fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
                offset=0
                while offset < len(content):
                    tick(until);count=os.write(fd,content[offset:offset+65536]);require(0 < count <= min(65536,len(content)-offset));offset+=count
                os.fchmod(fd,0o444);os.fsync(fd)
                held=full(os.fstat(fd));require(held == full(os.stat(name,dir_fd=directory,follow_symlinks=False)) and held[5] == 1)
                writers.append((fd,held));fd=None
            require(set(os.listdir(directory)) == set(FILES));source.recheck()
            for name,(writer,witness) in zip(FILES,writers):
                require(full(os.fstat(writer)) == witness == full(os.stat(name,dir_fd=directory,follow_symlinks=False)))
            os.fchmod(directory,0o555);os.fsync(directory);os.fsync(parent.fd)
            held=HeldPackage(root,until,expected=document);error=None
            try:
                held.full();source.recheck();parent.recheck()
                require(stable(os.fstat(directory))[:4] == created[:4]
                    and full(os.fstat(directory)) == full(os.stat(root.name,dir_fd=parent.fd,follow_symlinks=False)))
                for name,(writer,witness) in zip(FILES,writers):
                    require(full(os.fstat(writer)) == witness == full(os.stat(name,dir_fd=directory,follow_symlinks=False)))
                reference=held.reference()
            except BaseException as body:error=body;raise
            finally:
                try:held.close()
                except BaseException as cleanup:
                    if error is not None:cleanup_cause(error,cleanup)
                    raise
    except BaseException as error:
        failure=error
        raise
    finally:
        cleanup=None
        if fd is not None:
            for writer,unused in writers:
                if writer == fd:fd=None;break
        while writers:
            writer,unused=writers.pop()
            try:os.close(writer)
            except BaseException as error:
                if cleanup is None:cleanup=error
        for descriptor in (fd,directory):
            if descriptor is None:continue
            try:os.close(descriptor)
            except BaseException as error:
                if cleanup is None:cleanup=error
        try:parent.close()
        except BaseException as error:
            if cleanup is None:cleanup=error
        if cleanup is not None:
            if failure is not None:cleanup_cause(failure,cleanup)
            raise cleanup
    source.recheck();tick(until)
    return reference


def qualified_retained(selection, records, home, until):
    """Only a fresh held owner can consume recorded retention content."""
    reference=selection["retention"]
    root=retention_pin(reference,records,selection)
    held=HeldPackage(root,until)
    try:
        require(held.reference() == reference and held.document["producer_qualified"] is True)
        original=held.document["original"]
        import guard_resident_owned_update as owned
        owned.start_pins(original,home)
        require(all(held.document[name] == original[name] for name in ("archive_sha256","archive_bytes","manifest_sha256")))
        require({name:selection[name] for name in ("archive_sha256","archive_bytes","manifest_sha256","qualification")}
            == {name:original[name] for name in ("archive_sha256","archive_bytes","manifest_sha256","qualification")})
        q=original["qualification"]
        require(sha(held.qualification.raw) == q["sha256"] and len(held.qualification.raw) == q["bytes"])
        output=owned.qualification_output(decode(held.qualification.raw),q)
        require(Path(original["archive_path"]) == output/owned.ARCHIVE_RELATIVE)
        held.full();tick(until)
        return held
    except BaseException as error:
        try:held.close()
        except BaseException as cleanup:cleanup_cause(error,cleanup)
        raise
