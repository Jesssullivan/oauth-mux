"""Test-only health forwarding; reject and categorically journal every other frame.

The runner copies the declared existing bounded recorder implementation beside
this wrapper. No product source is altered; source operations are never forwarded.
"""
import json
import os
from pathlib import Path
import runpy
import sys


def health_only(frame, identity, implementation, journal):
    try:
        value = json.loads(frame[4:], object_pairs_hook=implementation["unique_fields"],
                           parse_constant=implementation["invalid_constant"])
        if type(value) is not dict or value.get("method") != "browser.health":
            raise ValueError("non_health")
        return implementation["project"](frame, identity)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        # Fixed fields only: the request ID, source, raw frame and error stay private.
        implementation["append"](journal, {"id": "omitted", "method": "unexpected_request", "sourceId": None})
        raise ValueError("toolbar_health_only_boundary") from None


def main():
    source = Path(__file__).absolute().with_name("recorder_implementation.py")
    implementation = runpy.run_path(str(source))
    configuration = implementation["private_file"](os.environ["OMUX_CHROMIUM_RECORDER_CONFIG"])
    implementation["require"](configuration.stat().st_size <= 4096)
    settings = json.loads(configuration.read_bytes())
    journal = implementation["private_file"](settings["journal"])
    namespace = implementation["main"].__globals__
    namespace["project"] = lambda frame, identity: health_only(frame, identity, implementation, journal)
    return implementation["main"]()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("toolbar native observer refused", file=sys.stderr)
        sys.exit(1)
