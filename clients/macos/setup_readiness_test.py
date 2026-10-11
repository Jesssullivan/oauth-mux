"""Run the declared Darwin fixture using the production Swift readiness parser."""
import subprocess
import sys

if len(sys.argv) != 2:
    raise SystemExit("one declared Swift fixture is required")
result = subprocess.run([sys.argv[1]], check=True, capture_output=True, text=True, timeout=30)
if result.stdout != "OMUX_SETUP_READINESS_FIXTURE_OK\n" or result.stderr:
    raise SystemExit("unexpected readiness fixture result")
