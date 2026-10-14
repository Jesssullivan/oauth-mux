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


def node_hash(lock, node):
    if not isinstance(node, str):
        raise ValueError("unsupported locked source indirection")
    locked = lock["nodes"][node]["locked"]
    sri = locked["narHash"]
    if not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", sri):
        raise ValueError("unsupported locked NAR")
    digest = base64.b64decode(sri.removeprefix("sha256-"), validate=True)
    if len(digest) != 32:
        raise ValueError("invalid locked NAR")
    return "sha256:" + digest.hex()


def locked_hash(lock):
    node = lock["nodes"][lock["root"]]["inputs"]["nixpkgs"]
    return node_hash(lock, node)


def native_source_hashes(lock):
    """The three source roles required by the committed native flake."""
    inputs = lock["nodes"][lock["root"]]["inputs"]
    utils = inputs["flake-utils"]
    if not isinstance(utils, str):
        raise ValueError("unsupported locked source indirection")
    systems = lock["nodes"][utils]["inputs"]["systems"]
    return {"nixpkgs": node_hash(lock, inputs["nixpkgs"]),
            "flake-utils": node_hash(lock, utils),
            "systems": node_hash(lock, systems)}


def locate(database, expected_hash, seconds=MAX_SECONDS, *, deadline=None):
    if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or not 0 < seconds <= MAX_SECONDS:
        raise ValueError("source metadata deadline")
    now = time.monotonic()
    if deadline is None:
        deadline = now + seconds
    elif not isinstance(deadline, (int, float)) or isinstance(deadline, bool):
        raise ValueError("source metadata deadline")
    remaining = deadline - now
    if not 0 < remaining <= seconds:
        raise ValueError("source metadata deadline")
    # mode=ro rejects absent databases and cannot create or mutate the store DB.
    # Do not use immutable=1: that would suppress SQLite's live WAL handling.
    uri = database.resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=min(2, remaining)) as connection:
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


def native_metadata(lock, database=DATABASE):
    # Every role shares one original deadline; later queries receive only the
    # remaining time. Matching store metadata is never source or build proof.
    deadline = time.monotonic() + MAX_SECONDS
    candidates = {}
    for role, expected in native_source_hashes(lock).items():
        remaining = deadline - time.monotonic()
        if not 0 < remaining <= MAX_SECONDS:
            raise ValueError("source metadata deadline")
        candidates[role] = locate(database, expected, seconds=remaining, deadline=deadline)
    if time.monotonic() >= deadline:
        raise ValueError("source metadata deadline")
    return {"scope": "local-operator-bootstrap-metadata",
            "passed": all(candidates.values()), "source_candidates": candidates,
            "byte_verification": "pending-declared-nar-action",
            "source_nar_verified": False, "build_seed_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--native-inputs", action="store_true",
                        help="Locate nixpkgs, flake-utils and systems under one deadline.")
    args = parser.parse_args()
    try:
        with Path(args.lock).open("rb") as reader:
            data = reader.read(1048577)
        if len(data) > 1048576:
            raise ValueError("lock input bound")
        lock = json.loads(data)
        if args.native_inputs:
            result = native_metadata(lock)
            print(json.dumps(result, sort_keys=True))
            return 0 if result["passed"] else 2
        matches = locate(DATABASE, locked_hash(lock))
        print(json.dumps({"scope": "local-operator-bootstrap-metadata", "passed": bool(matches),
                          "source_candidates": matches, "byte_verification": "pending-declared-nar-action"}, sort_keys=True))
        return 0 if matches else 2
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error):
        print(json.dumps({"scope": "local-operator-bootstrap-metadata", "passed": False,
                          "source_candidates": [], "gate": "read-only-source-metadata-unavailable"}, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
