"""Validate public candidate closure metadata with bootstrap Python only."""
import hashlib
import json
from pathlib import Path
import sys

from cached_nix_inventory import roots_from_input
from verify_cached_nars import MAX_INPUT, parse_inventory


def validate(content, digest):
    parse_inventory(content, digest)
    value = json.loads(content)
    expected = {'schemaVersion', 'system', 'mode', 'provenance', 'roots', 'packages', 'helperTools', 'paths', 'contentRehashed', 'realized', 'published'}
    if set(value) != expected or value['mode'] != 'local-sqlite-readonly-snapshot':
        raise ValueError('unexpected-candidate-fields')
    roots = roots_from_input(value)
    if roots != value['roots'] or value['contentRehashed'] is not False or value['realized'] is not False or value['published'] is not False:
        raise ValueError('candidate-claim-boundary')
    graph = {row['path']: row['references'] for row in value['paths']}
    def closure(selected):
        seen = set()
        pending = list(selected)
        while pending:
            item = pending.pop()
            if item not in seen:
                seen.add(item)
                pending.extend(graph[item])
        return sorted(seen)
    packages = value['packages']
    return {'schemaVersion': 1, 'sha256': digest, 'packages': packages,
            'allPaths': sorted(graph),
            'nodePaths': closure([packages[key]['out'] for key in ('node', 'python', 'pnpm', 'bash', 'coreutils')] + value['helperTools']),
            'browserPaths': closure([packages[key]['out'] for key in ('chromium', 'bash', 'coreutils')]),
            'qualification': 'pending-nar-and-shared-selection-actions'}


if __name__ == '__main__':
    with open(sys.argv[1], 'rb') as stream:
        content = stream.read(MAX_INPUT + 1)
    try:
        print(json.dumps(validate(content, sys.argv[2]), sort_keys=True))
    except (ValueError, KeyError, TypeError):
        raise SystemExit('candidate inventory rejected')
