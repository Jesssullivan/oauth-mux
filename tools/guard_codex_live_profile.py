"""Exact opt-in Codex live action; private paths never become evidence.

This is operator-input admission, not provider authorization or continuity proof.
Only the contained proof daemon reads the selected native-store credential files.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

LABEL = "//delivery:installed_codex_live_continuity_test"
ENROLLMENT_LABEL = "//delivery:installed_codex_live_enrollment_test"
LABELS = frozenset((LABEL, ENROLLMENT_LABEL))
DESTINATION = "/omux-live-inputs/input.json"
VARIABLE = "OMUX_CODEX_LIVE_INPUT_MANIFEST"
MAX_MANIFEST = 65536
MAX_SOURCE = 1024 * 1024

def selected(arguments):
    if len(arguments) != 2 or arguments[0] != "test" or arguments[1] not in LABELS:
        raise ValueError("codex-live-exact-target")
    return {"PrivateNetwork": "no"}

def finite(arguments, manager, manifest, runtime_directory, reuse, unrelated=()):
    selected(arguments)
    if (manager != "system" or manifest is None
            or (arguments[1] == LABEL and runtime_directory is None)
            or (arguments[1] == ENROLLMENT_LABEL and runtime_directory is not None)
            or reuse or any(unrelated)):
        raise ValueError("codex-live-private-input-profile")

def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

def open_private(path, maximum, read=False):
    value = str(path)
    if (not value.startswith("/") or value.endswith("/") or len(os.fsencode(value)) > 4096
            or any(part in ("", ".", "..") for part in value.split("/")[1:])
            or any(char in value for char in "\\\n\r\x00")):
        raise ValueError("codex-live-private-input-selector")
    parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in Path(value).parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
            info = os.fstat(parent)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError("codex-live-private-input-ancestor")
        fd = os.open(Path(value).name,
                     (os.O_RDONLY | os.O_NONBLOCK if read else os.O_PATH) | os.O_NOFOLLOW,
                     dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) not in (0o400, 0o600)
                    or info.st_nlink != 1 or not 0 < info.st_size <= maximum):
                raise ValueError("codex-live-private-input-custody")
            return fd
        except BaseException:
            os.close(fd)
            raise
    finally:
        os.close(parent)

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("codex-live-private-input-duplicate-field")
        result[key] = value
    return result

def open_manifest_directory(manifest):
    path = Path(manifest)
    if path.name != 'input.json' or not path.is_absolute():
        raise ValueError('codex-live-manifest-namespace')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError('codex-live-manifest-ancestor')
        info = os.fstat(descriptor)
        if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700
                or os.listdir(descriptor) != ['input.json']):
            raise ValueError('codex-live-manifest-private-directory')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

def binding_selector(value):
    if not isinstance(value, str) or ':' in value or '\\' in value or any(char.isspace() for char in value):
        raise ValueError('codex-live-bind-selector')
    return value

def receipt_properties(observed, verified=False):
    """A copied evidence view; effective bind selectors stay private."""
    result = dict(observed)
    result["BindReadOnlyPaths"] = ("verified-private-input:" + DESTINATION
                                    if verified else "private-input-bind-redacted")
    result["BindPaths"] = "none" if verified else "private-input-bind-redacted"
    return result

def rejection_category(error):
    """Do not stringify OSError or native/provider exception content."""
    return "codex-live-admission-refused"

def verify_binding(observed, expected):
    entries = observed.get('BindReadOnlyPaths', '').split()
    if len(entries) != 1 or observed.get('BindPaths', '').strip():
        raise ValueError('codex-live-private-bind-rejected')
    parts = entries[0].split(':')
    required = expected.split(':')
    if (len(parts) not in (2, 3) or parts[:2] != required
            or len(parts) == 3 and parts[2] != 'rbind'):
        raise ValueError('codex-live-private-bind-rejected')

def binding_facts(observed, expected):
    # Explicit shape predicates only; never retain mount source selectors.
    entries = observed.get('BindReadOnlyPaths', '').split()
    parts = entries[0].split(':') if len(entries) == 1 else []
    required = expected.split(':')
    return {'entry_count': min(len(entries), 2), 'part_count': min(len(parts), 4),
            'source_matches': bool(parts) and parts[0] == required[0],
            'destination_matches': len(parts)>1 and parts[1] == required[1],
            'option': 'absent' if len(parts)==2 else 'rbind' if len(parts)==3 and parts[2]=='rbind' else 'unrecognized',
            'writable_bind_present': bool(observed.get('BindPaths','').strip())}

def schema(raw, label=LABEL):
    if label not in LABELS:
        raise ValueError("codex-live-exact-target")
    fields = {"schema_version", "authorized_source_paths"}
    count = 1 if label == ENROLLMENT_LABEL else 2
    if label == LABEL:
        fields.add("model")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if (not isinstance(value, dict) or set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not isinstance(value["authorized_source_paths"], list)
            or len(value["authorized_source_paths"]) != count
            or any(not isinstance(path, str) for path in value["authorized_source_paths"])
            or len(set(value["authorized_source_paths"])) != count
            or label == LABEL and (not isinstance(value["model"], str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value["model"]))):
        raise ValueError("codex-live-private-input-schema")
    return value

class Admission:
    def __init__(self, manifest, source_root, deadline_ns, arguments):
        selected(arguments)
        self.label = arguments[1]
        self.count = 1 if self.label == ENROLLMENT_LABEL else 2
        self.manifest = Path(binding_selector(str(manifest)))
        self.source_root = Path(source_root).resolve(strict=True)
        self.deadline_ns = deadline_ns
        self.descriptors = []
        self.paths = []
        self.identities = []
        self.parent_fd = None
        self.parent_identity = None
        try:
            if self.manifest.is_relative_to(self.source_root):
                raise ValueError("codex-live-private-input-in-source")
            self.parent_fd = open_manifest_directory(self.manifest)
            self.parent_identity = identity(os.fstat(self.parent_fd))
            fd = open_private(self.manifest, MAX_MANIFEST, read=True)
            self.descriptors.append(fd)
            self.paths.append(self.manifest)
            self.identities.append(identity(os.fstat(fd)))
            raw = os.read(fd, MAX_MANIFEST + 1)
            if len(raw) != self.identities[0][5]:
                raise ValueError("codex-live-private-input-read")
            value = schema(raw, self.label)
            self.manifest_digest = hashlib.sha256(raw).digest()
            for path in value["authorized_source_paths"]:
                selected_path = Path(path)
                if selected_path.is_relative_to(self.source_root):
                    raise ValueError("codex-live-source-in-repository")
                selected_fd = open_private(selected_path, MAX_SOURCE)
                self.descriptors.append(selected_fd)
                self.paths.append(selected_path)
                self.identities.append(identity(os.fstat(selected_fd)))
            if len({item[:2] for item in self.identities}) != len(self.identities):
                raise ValueError("codex-live-private-input-alias")
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        if time.monotonic_ns() >= self.deadline_ns:
            raise ValueError("codex-live-input-deadline")
        named_parent = open_manifest_directory(self.manifest)
        try:
            if (identity(os.fstat(self.parent_fd)) != self.parent_identity
                    or identity(os.fstat(named_parent)) != self.parent_identity
                    or identity(os.stat('input.json', dir_fd=self.parent_fd, follow_symlinks=False))
                    != self.identities[0]):
                raise ValueError('codex-live-manifest-directory-changed')
        finally:
            os.close(named_parent)
        for index, (path, fd, expected) in enumerate(zip(self.paths, self.descriptors, self.identities)):
            named = open_private(path, MAX_MANIFEST if index == 0 else MAX_SOURCE)
            try:
                if identity(os.fstat(fd)) != expected or identity(os.fstat(named)) != expected:
                    raise ValueError("codex-live-private-input-changed")
            finally:
                os.close(named)
        os.lseek(self.descriptors[0], 0, os.SEEK_SET)
        raw = os.read(self.descriptors[0], MAX_MANIFEST + 1)
        if hashlib.sha256(raw).digest() != self.manifest_digest:
            raise ValueError("codex-live-private-input-changed")
        return {"schemaVersion": 1, "selectedSources": self.count, "custodyVerified": True,
                "sourceContentReadByGuard": False}

    def runtime_seconds(self):
        remaining = (self.deadline_ns - time.monotonic_ns() - 30 * 10**9) // 10**9
        if remaining < 1:
            raise ValueError("codex-live-input-deadline")
        return min(1200, remaining)

    def binding(self):
        return str(self.manifest.parent) + ":" + str(Path(DESTINATION).parent)

    def close(self):
        descriptors, self.descriptors = self.descriptors, []
        for fd in descriptors:
            os.close(fd)
        if self.parent_fd is not None:
            descriptor, self.parent_fd = self.parent_fd, None
            os.close(descriptor)
