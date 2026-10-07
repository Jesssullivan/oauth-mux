"""Provider-free ordinary launch/resume of an independently pinned fresh runtime.

No LiveScenario, manifest, source enrollment or provider turn is constructed.
The original fixture owns the disposable vault/daemon and every history check.
"""
from pathlib import Path
import sys

# The declared launcher adds only this main file's directory. Use the
# lexical runfiles sibling supplied by codex_fresh_live_support; never
# resolve to an ambient source checkout or add an undeclared fallback.
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

import test_installed_native_tui as tui
import test_installed_codex_live_continuity as runtime_support


def qualified_reader(pin):
    return lambda candidate, receipt: runtime_support.fresh_runtime_bundle(candidate, receipt, pin)


def main():
    kind, pin, arguments = runtime_support.runtime_arguments(sys.argv[1:])
    tui.require(kind == "fresh" and pin is not None, "fresh ordinary runtime selection required")
    sys.argv[1:] = arguments
    return tui.main(runtime_reader=qualified_reader(pin), entrypoint=Path(__file__).absolute(),
                    entrypoint_args=("--runtime-kind=fresh", "--runtime-pin=" + str(pin)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Preserve the parent fixture's finite private-child phase scanner.
        print("installed native terminal proof failed at " + tui.PHASE, file=sys.stderr)
        sys.exit(1)
