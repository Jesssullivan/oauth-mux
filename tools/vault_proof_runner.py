"""Run isolated real-vault proofs with declared tools and bounded cleanup."""
import argparse
import os
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bash", required=True)
    parser.add_argument("--coreutils", required=True)
    parser.add_argument("script")
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    environment = os.environ.copy()
    environment["PATH"] = args.coreutils
    environment["BASH"] = args.bash
    process = subprocess.Popen(
        [args.bash, args.script, *args.arguments], env=environment,
        start_new_session=True,
    )
    try:
        return process.wait(timeout=90)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        print("isolated native custody proof exceeded bounded execution", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
