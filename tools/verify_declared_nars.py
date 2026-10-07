"""Hash NAR descriptors using only their declared indexed regular-file labels."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from nar_descriptor import hash_descriptor, open_regular, validate_descriptor
from verify_cached_nars import MAX_BYTES, MAX_INPUT, expected_hash, parse_inventory

MAX_DESCRIPTOR_BYTES = 256 * 1024 * 1024


def open_declared(label, physical_label, expected_source, node):
    physical_labels = physical_label if isinstance(physical_label, (list, tuple)) else [physical_label]
    allowed = {Path(label).absolute(), *(Path(item).absolute() for item in physical_labels)}
    current = Path(label).absolute()
    for _ in range(8):
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(current)
            target = Path(os.path.normpath(target if os.path.isabs(target) else str(current.parent / target)))
            if target == Path(expected_source):
                stream = open_regular(str(target), '')
                break
            if target not in allowed:
                raise ValueError('undeclared-label-alias')
            current = target
        elif stat.S_ISREG(metadata.st_mode):
            stream = open_regular(str(current), '')
            break
        else:
            raise ValueError('declared-label-not-regular')
    else:
        raise ValueError('declared-label-hop-bound')
    actual = os.fstat(stream.fileno())
    if actual.st_size != node['size'] or bool(actual.st_mode & stat.S_IXUSR) != node['executable']:
        stream.close()
        raise ValueError('declared-regular-metadata-changed')
    return stream


def verify(inventory_bytes, digest, descriptor_bytes, label_root, physical_root):
    rows = parse_inventory(inventory_bytes, digest)
    if len(descriptor_bytes) > MAX_DESCRIPTOR_BYTES:
        raise ValueError('descriptor-byte-bound')
    bundle = json.loads(descriptor_bytes)
    if set(bundle) != {'schemaVersion', 'inventorySha256', 'roots'} or bundle['schemaVersion'] != 1 or bundle['inventorySha256'] != digest:
        raise ValueError('descriptor-inventory-binding')
    expected = {row['path']: row for row in rows}
    if len(bundle['roots']) != len(expected):
        raise ValueError('descriptor-root-count')
    seen, labels = set(), set()
    total = 0
    global_deadline = time.monotonic() + 600
    for item in bundle['roots']:
        if set(item) != {'descriptor', 'regularInputs'}:
            raise ValueError('descriptor-item-fields')
        descriptor = item['descriptor']
        nodes, _ = validate_descriptor(descriptor)
        root = descriptor['root']
        if root in seen or root not in expected:
            raise ValueError('descriptor-root-set')
        seen.add(root)
        regular = {path for path, node in nodes.items() if node['type'] == 'regular'}
        mapping = item['regularInputs']
        if set(mapping) != regular:
            raise ValueError('descriptor-regular-label-set')
        for label in mapping.values():
            if not isinstance(label, str) or not re.fullmatch(r'regular/[0-9]{8}', label) or label in labels:
                raise ValueError('descriptor-label')
            labels.add(label)
        def opener(selected_root, path):
            if selected_root != root or path not in mapping:
                raise ValueError('undeclared-regular-input')
            label = mapping[path]
            roots = physical_root if isinstance(physical_root, (list, tuple)) else [physical_root]
            return open_declared(Path(label_root) / label, [Path(root) / label for root in roots],
                                 str(Path(root) / path), nodes[path])
        result = hash_descriptor(descriptor, opener=opener,
                                 deadline=min(global_deadline, time.monotonic() + 120))
        if result['narSize'] != expected[root]['narSize'] or result['narHash'][7:] != expected_hash(expected[root]['narHash']):
            raise ValueError('descriptor-nar-mismatch')
        total += result['narSize']
        if total > MAX_BYTES:
            raise ValueError('aggregate-nar-byte-bound')
    return {'schemaVersion': 1, 'passed': True, 'inventorySha256': digest,
            'descriptorSha256': hashlib.sha256(descriptor_bytes).hexdigest(),
            'verifiedPaths': len(seen), 'verifiedRegularInputs': len(labels), 'verifiedNarBytes': total,
            'contentRehashed': True, 'linkTargetsFollowed': False, 'executionAuthority': False,
            'flakeMappingVerified': False, 'realized': False}


def metadata_alias_roots(selected):
    selected = Path(selected).absolute()
    roots = {selected.parent, selected.resolve(strict=True).parent}
    if selected.is_symlink():
        target = os.readlink(selected)
        target = Path(os.path.normpath(target if os.path.isabs(target) else str(selected.parent / target)))
        roots.add(target.parent)
    return sorted(roots)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--descriptors', required=True)
    args = parser.parse_args()
    try:
        with open(args.inventory, 'rb') as stream:
            inventory = stream.read(MAX_INPUT + 1)
        with open(args.descriptors, 'rb') as stream:
            descriptors = stream.read(MAX_DESCRIPTOR_BYTES + 1)
        selected = Path(args.descriptors).absolute()
        # Only the already-declared public metadata label determines the two
        # legitimate Bazel alias namespaces; regular inputs have no fallback.
        roots = metadata_alias_roots(selected)
        print(json.dumps(verify(inventory, args.sha256, descriptors, selected.parent, roots), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({'schemaVersion': 1, 'passed': False, 'gate': 'declared-nar-byteproof-unavailable'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
