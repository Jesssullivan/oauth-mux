"""Exact runtime009 ordinary launch/rename/export/empty cold resume entrypoint.

Uses actual committed daemon discovery and legacy detach/durable inspectors.
Export denotes PTY input submission followed by observed preservation; no
command dispatch, processing or completion acknowledgment is established.
Never enters the old seeded default, invents native status, submits provider
work or claims resident/accepted-history/same-process handoff support.
"""
from pathlib import Path
import sys

import test_installed_legacy_native_tui as legacy


def main():
    return legacy.main(ordinary_first=True, entrypoint=Path(__file__).absolute())


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed legacy native terminal proof failed at " + legacy.PHASE, file=sys.stderr)
        sys.exit(1)
