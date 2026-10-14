"""Fixed registration collector under the distinct reserved action clock."""
import json
import os
import sqlite3
import sys
import time
import codex_query_registration as registration
import guard_query_registration_reserved as reserved


def main():
    deadline = reserved.collector_deadline(os.environ, time.monotonic_ns())
    registration.main(absolute_deadline=deadline)


if __name__ == "__main__":
    try:
        main()
    except registration.MissingRoots as failure:
        print(json.dumps({"passed": False, "reason": "missing-fixed-roots", "roles": failure.roles}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1) from None
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, json.JSONDecodeError, sqlite3.Error):
        print('{"passed":false,"reason":"bounded-public-registration-unavailable"}', file=sys.stderr)
        raise SystemExit(1) from None
