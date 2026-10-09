"""Exact runtime009 ordinary launch/export/rename/empty cold resume entrypoint.

Uses actual committed daemon discovery and legacy detach/durable inspectors.
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
