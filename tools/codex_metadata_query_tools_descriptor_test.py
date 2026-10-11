"""Read the genuine generated descriptor, with full declared tool NAR proof, no query/native/source/SDK execution."""
import json
import os
from pathlib import Path
import sys
import time
import codex_protocol_history_metadata_producer as producer

def main():
    producer.require(len(sys.argv) == 1)
    entry=float(time.monotonic())
    seconds=min(840,int(os.environ["TEST_TIMEOUT"])-60)
    producer.require(1<=seconds<=840)
    producer.DEADLINE=producer.query_tools.consumer_deadline(entry,seconds)
    runfiles = Path(os.environ["TEST_SRCDIR"]).resolve(strict=True)
    with (runfiles/"_repo_mapping").open("rb") as stream:
        raw = stream.read(1024*1024 + 1)
    producer.require(len(raw) <= 1024*1024)
    rows = [line.split(",") for line in raw.decode().splitlines()]
    producer.require(producer.declared_query_tools(runfiles, rows) is True)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        print("declared-metadata-query-tools-refused", file=sys.stderr)
        sys.exit(125)
