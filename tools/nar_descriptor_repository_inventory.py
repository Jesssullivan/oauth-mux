"""Bootstrap-only creation of byte-proof descriptors and indexed regular labels."""
import json
from pathlib import Path
import sys

from nar_descriptor import MAX_ENTRIES, MAX_METADATA_BYTES, describe
from verify_cached_nars import MAX_INPUT, parse_inventory


def generate(content, digest, repository):
    rows = parse_inventory(content, digest)
    roots = []
    inputs = []
    node_count = 0
    for row in rows:
        descriptor = describe(row['path'])
        node_count += len(descriptor['nodes'])
        if node_count > MAX_ENTRIES:
            raise ValueError('aggregate-descriptor-entry-bound')
        mapped = {}
        for node in descriptor['nodes']:
            if node['type'] == 'regular':
                label = 'regular/' + str(len(inputs)).zfill(8)
                source = str(Path(row['path']) / node['path'])
                inputs.append({'label': label, 'source': source})
                mapped[node['path']] = label
        roots.append({'descriptor': descriptor, 'regularInputs': mapped})
    bundle = {'schemaVersion': 1, 'inventorySha256': digest, 'roots': roots}
    target = Path(repository) / 'nar-descriptors.json'
    encoded = json.dumps(bundle, sort_keys=True)
    if len(encoded.encode()) > MAX_METADATA_BYTES:
        raise ValueError('aggregate-descriptor-byte-bound')
    target.write_text(encoded, encoding='utf-8')
    return {'regularInputs': inputs, 'roots': len(roots), 'descriptorBytes': target.stat().st_size}


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as stream:
        content = stream.read(MAX_INPUT + 1)
    print(json.dumps(generate(content, sys.argv[2], sys.argv[3]), sort_keys=True))
