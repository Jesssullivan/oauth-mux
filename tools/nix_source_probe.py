"""Local operator bootstrap metadata, not a hermetic test or release proof.

Read-only SQLite access identifies source candidates for the exact locked NAR.
The later declared NAR verification action remains authoritative for bytes.
"""
import argparse
import base64
import json
from pathlib import Path
import re
import sqlite3
import time

DATABASE = Path("/nix/var/nix/db/db.sqlite")
MAX_SECONDS = 10
MAX_MATCHES = 8


def locked_hash(lock):
    node = lock["nodes"][lock["root"]]["inputs"]["nixpkgs"]
    locked = lock["nodes"][node]["locked"]
    sri = locked["narHash"]
    if not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", sri):
        raise ValueError("unsupported locked NAR")
    digest = base64.b64decode(sri.removeprefix("sha256-"), validate=True)
    if len(digest) != 32:
        raise ValueError("invalid locked NAR")
    return "sha256:" + digest.hex()


def locate(database, expected_hash, seconds=MAX_SECONDS):
    deadline = time.monotonic() + seconds
    # mode=ro rejects absent databases and cannot create or mutate the store DB.
    # Do not use immutable=1: that would suppress SQLite's live WAL handling.
    uri = database.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=min(2, seconds)) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        schema = connection.execute("PRAGMA table_info(ValidPaths)").fetchall()
        columns = {row[1] for row in schema}
        # Nix schema revisions use 'hash' or 'narHash'. Only these two fixed
        # identifiers are eligible; no caller SQL or schema values enter SQL.
        hash_column = "narHash" if "narHash" in columns else "hash" if "hash" in columns else None
        if "path" not in columns or hash_column is None:
            raise ValueError("unsupported Nix database schema")
        queries = {
            "hash": "SELECT path FROM ValidPaths WHERE hash = ? LIMIT 9",
            "narHash": "SELECT path FROM ValidPaths WHERE narHash = ? LIMIT 9",
        }
        rows = connection.execute(queries[hash_column], (expected_hash,)).fetchall()
        if len(rows) > MAX_MATCHES or time.monotonic() >= deadline:
            raise ValueError("bounded source metadata unavailable")
    matches = []
    for (raw_path,) in rows:
        if time.monotonic() >= deadline:
            raise ValueError("source metadata deadline")
        # Emit only public immutable source roots, never arbitrary DB content.
        if not isinstance(raw_path, str) or not re.fullmatch(r"/nix/store/[0-9a-z]{32}-(?:[A-Za-z0-9._+-]{1,180}-)?source", raw_path):
            continue
        path = Path(raw_path)
        if path.is_dir() and not path.is_symlink():
            matches.append(raw_path)
    return sorted(set(matches))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    args = parser.parse_args()
    try:
        with Path(args.lock).open("rb") as reader:
            data = reader.read(1048577)
        if len(data) > 1048576:
            raise ValueError("lock input bound")
        matches = locate(DATABASE, locked_hash(json.loads(data)))
        print(json.dumps({"scope": "local-operator-bootstrap-metadata", "passed": bool(matches),
                          "source_candidates": matches, "byte_verification": "pending-declared-nar-action"}, sort_keys=True))
        return 0 if matches else 2
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        print(json.dumps({"scope": "local-operator-bootstrap-metadata", "passed": False,
                          "source_candidates": [], "gate": "read-only-source-metadata-unavailable"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
