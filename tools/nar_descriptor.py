"""Canonical streaming NAR hashing from regular inputs and inert link metadata.

Specification: https://nix.dev/manual/nix/2.34/protocols/nix-archive
This byte-proof graph never grants permission to resolve or execute link targets.
"""
import hashlib
import os
from pathlib import Path
import stat
import struct
import time

MAX_ENTRIES = 1000000
MAX_BYTES = 16 * 1024 * 1024 * 1024
MAX_DEPTH = 256
MAX_METADATA_BYTES = 256 * 1024 * 1024


def relative_name(value):
    if not isinstance(value, str) or '\x00' in value or len(os.fsencode(value)) > 4096:
        raise ValueError('descriptor-path')
    parts = value.split('/') if value else []
    if len(parts) > MAX_DEPTH or any(part in ('', '.', '..') for part in parts):
        raise ValueError('descriptor-traversal')
    return parts


def validate_descriptor(value):
    if not isinstance(value, dict) or set(value) != {'schemaVersion', 'root', 'nodes'} or value['schemaVersion'] != 1:
        raise ValueError('descriptor-schema')
    root = value['root']
    if not isinstance(root, str) or not Path(root).is_absolute() or any(part in ('.', '..') for part in root.split('/')) or '\x00' in root:
        raise ValueError('descriptor-input-root')
    nodes = value['nodes']
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_ENTRIES:
        raise ValueError('descriptor-entry-bound')
    by_path = {}
    children = {}
    expected_bytes = 0
    for node in nodes:
        parts = relative_name(node['path'])
        path = node['path']
        if path in by_path:
            raise ValueError('descriptor-duplicate')
        kind = node['type']
        keys = {'path', 'type'}
        if kind == 'regular':
            keys |= {'size', 'executable'}
            if type(node['size']) is not int or node['size'] < 0 or type(node['executable']) is not bool:
                raise ValueError('descriptor-regular')
            expected_bytes += node['size']
        elif kind == 'symlink':
            keys.add('target')
            if not isinstance(node['target'], str) or '\x00' in node['target'] or len(os.fsencode(node['target'])) > 65536:
                raise ValueError('descriptor-link')
        elif kind != 'directory':
            raise ValueError('descriptor-special-file')
        if set(node) != keys or expected_bytes > MAX_BYTES:
            raise ValueError('descriptor-fields-or-byte-bound')
        by_path[path] = node
        if parts:
            parent = '/'.join(parts[:-1])
            children.setdefault(parent, []).append(parts[-1])
    if '' not in by_path:
        raise ValueError('descriptor-root')
    for parent in children:
        if parent not in by_path or by_path[parent]['type'] != 'directory':
            raise ValueError('descriptor-parent-not-directory')
    return by_path, children


def describe(root):
    """Read only lstat/readlink metadata; never recurse through a symlink."""
    root = Path(root)
    nodes = []
    metadata_bytes = 0
    pending = [('', root)]
    while pending:
        relative, path = pending.pop()
        relative_name(relative)
        if len(nodes) >= MAX_ENTRIES:
            raise ValueError('descriptor-entry-bound')
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode):
            node = {'path': relative, 'type': 'symlink', 'target': os.readlink(path)}
        elif stat.S_ISDIR(metadata.st_mode):
            node = {'path': relative, 'type': 'directory'}
            with os.scandir(path) as entries:
                names = [entry.name for entry in entries]
            if len(names) > MAX_ENTRIES:
                raise ValueError('descriptor-directory-bound')
            for name in names:
                child = relative + '/' + name if relative else name
                pending.append((child, path / name))
        elif stat.S_ISREG(metadata.st_mode):
            node = {'path': relative, 'type': 'regular', 'size': metadata.st_size,
                    'executable': bool(metadata.st_mode & stat.S_IXUSR)}
        else:
            raise ValueError('descriptor-special-file')
        metadata_bytes += len(os.fsencode(relative)) + 128
        if node['type'] == 'symlink':
            metadata_bytes += len(os.fsencode(node['target']))
        if metadata_bytes > MAX_METADATA_BYTES:
            raise ValueError('descriptor-metadata-bound')
        nodes.append(node)
    descriptor = {'schemaVersion': 1, 'root': str(root), 'nodes': sorted(nodes, key=lambda node: os.fsencode(node['path']))}
    validate_descriptor(descriptor)
    return descriptor


def open_regular(root, relative):
    """Reject link-bearing directories and the final link before reading bytes."""
    path = Path(root)
    if not path.is_absolute():
        raise ValueError('descriptor-input-root')
    parts = list(path.parts[1:]) + relative_name(relative)
    if not parts:
        raise ValueError('descriptor-input-root')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        if not stat.S_ISREG(os.fstat(file_descriptor).st_mode):
            os.close(file_descriptor)
            raise ValueError('descriptor-input-not-regular')
        return os.fdopen(file_descriptor, 'rb')
    finally:
        os.close(descriptor)


def serialize(descriptor, emit, opener=open_regular, deadline=None):
    by_path, children = validate_descriptor(descriptor)
    deadline = deadline if deadline is not None else time.monotonic() + 120
    emitted = 0
    def write(content):
        nonlocal emitted
        emitted += len(content)
        if emitted > MAX_BYTES or time.monotonic() > deadline:
            raise ValueError('nar-output-or-deadline-bound')
        emit(content)
    def string(content):
        content = os.fsencode(content) if isinstance(content, str) else content
        write(struct.pack('<Q', len(content)))
        write(content)
        write(b'\0' * (-len(content) % 8))
    def node(path):
        item = by_path[path]
        string('(')
        string('type')
        string(item['type'])
        if item['type'] == 'directory':
            for name in sorted(children.get(path, []), key=os.fsencode):
                string('entry'); string('('); string('name'); string(name); string('node')
                node(path + '/' + name if path else name)
                string(')')
        elif item['type'] == 'symlink':
            string('target'); string(item['target'])
        else:
            if item['executable']:
                string('executable'); string('')
            string('contents')
            write(struct.pack('<Q', item['size']))
            with opener(descriptor['root'], path) as stream:
                if opener is open_regular:
                    actual = os.fstat(stream.fileno())
                    if actual.st_size != item['size'] or bool(actual.st_mode & stat.S_IXUSR) != item['executable']:
                        raise ValueError('descriptor-input-metadata-changed')
                remaining = item['size']
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise ValueError('nar-input-truncated')
                    remaining -= len(chunk)
                    write(chunk)
                if stream.read(1):
                    raise ValueError('nar-input-grew')
            write(b'\0' * (-item['size'] % 8))
        string(')')
    string('nix-archive-1')
    node('')
    return emitted



def serialized_size(descriptor, *, deadline):
    """Metadata-only canonical wire size; this is not a content/hash proof."""
    by_path, children = validate_descriptor(descriptor)
    def string_size(content):
        size = len(os.fsencode(content))
        return 8 + size + (-size % 8)
    def node_size(path):
        if time.monotonic() >= deadline:
            raise ValueError('nar-output-or-deadline-bound')
        item = by_path[path]
        count = string_size('(') + string_size('type') + string_size(item['type'])
        if item['type'] == 'directory':
            for name in children.get(path, []):
                count += sum(string_size(token) for token in ('entry', '(', 'name', name, 'node', ')'))
                count += node_size(path + '/' + name if path else name)
        elif item['type'] == 'symlink':
            count += string_size('target') + string_size(item['target'])
        else:
            if item['executable']:
                count += string_size('executable') + string_size('')
            count += string_size('contents') + 8 + item['size'] + (-item['size'] % 8)
        count += string_size(')')
        if count > MAX_BYTES:
            raise ValueError('nar-output-or-deadline-bound')
        return count
    count = string_size('nix-archive-1') + node_size('')
    if count > MAX_BYTES or time.monotonic() >= deadline:
        raise ValueError('nar-output-or-deadline-bound')
    return count

def hash_descriptor(descriptor, opener=open_regular, deadline=None):
    digest = hashlib.sha256()
    count = serialize(descriptor, digest.update, opener=opener, deadline=deadline)
    return {'narHash': 'sha256:' + digest.hexdigest(), 'narSize': count,
            'linkTargetsFollowed': False, 'executionAuthority': False}
