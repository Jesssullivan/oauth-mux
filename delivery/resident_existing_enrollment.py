"""Enroll an authorized native source using independently qualified installed software."""
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_enrollment_profile as guard
import guard_resident_owned_update as owned
import resident_enrollment as resident

def execute_existing(systemctl,session_probe,manifest):
    deadline = resident.original_deadline(os.environ)
    home = Path(os.environ["HOME"])
    guard.manifest_schema(manifest,home)
    guard.carrier_purpose(guard.EXISTING_ENROLLMENT_LABEL,manifest["action"],"existing_archive" in manifest)
    resident.PHASE = "installation"
    witness = owned.QualifiedExistingEnrollment(manifest,home,deadline-resident.CLEANUP_RESERVE_NS)
    try:
        base = {key:value for key,value in manifest.items() if key != "existing_archive"}
        # Full bundle verification, source O_PATH checks, installed inventory,
        # owned active responder/vault, provider verification and explicit
        # retained restart all remain the existing enrollment implementation.
        result = resident.execute(Path(witness.selection["archive_path"]),systemctl,session_probe,base)
        witness.recheck()
        return result
    finally:
        witness.close()

def main():
    resident.DEADLINE_NS = resident.original_deadline(os.environ)
    resident.require(len(sys.argv) == 3)
    systemctl,session_probe = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    selected = resident.private_manifest(validator=lambda value: guard.manifest_schema(value,Path(os.environ["HOME"])))
    result = execute_existing(systemctl,session_probe,selected)
    print(json.dumps(result,sort_keys=True,separators=(",", ":")))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError,ValueError,KeyError,TypeError,subprocess.TimeoutExpired):
        phase = resident.PHASE if resident.PHASE in resident.PHASES else "manifest"
        print("resident enrollment refused at " + phase,file=sys.stderr)
        sys.exit(125)
