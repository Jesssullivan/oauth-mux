"""Declared synthetic comparison with pinned Nix; no live store claim."""
import argparse
import json
import os
from pathlib import Path
import tempfile
import time

from nar_descriptor import describe, hash_descriptor
from verify_cached_nars import stream_nar


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nix', required=True)
    args = parser.parse_args()
    nix = str(Path(args.nix).resolve(strict=True))
    if not nix.startswith('/nix/store/') or not os.access(nix, os.X_OK):
        raise ValueError('pinned-nix-required')
    with tempfile.TemporaryDirectory(prefix='omux-nar-fixture-') as directory:
        root = Path(directory) / 'fixture'
        root.mkdir()
        (root / 'z').write_bytes(b'abc\x00defgh')
        (root / 'a').write_bytes(b'executable')
        (root / 'a').chmod(0o700)
        (root / 'empty').mkdir()
        (root / 'inert').symlink_to('/outside/never-read')
        for fixture in (root, root / 'a', root / 'inert'):
            expected = hash_descriptor(describe(fixture))
            stream_nar(nix, {'path': str(fixture), **expected}, time.monotonic() + 120)
    print(json.dumps({'passed': True, 'syntheticFixtureOnly': True, 'canonicalNarMatchesPinnedNix': True, 'storeClosureVerified': False}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
