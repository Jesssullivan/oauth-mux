"""Record an explicit operator statement after the indicated actual UI actions.

Manual declared Bazel target only. This writes an attestation, never browser
state or permissions. Observed Chrome predicates must be collected separately.
"""
import argparse
import json
import os
from pathlib import Path
import sys

import yoga_toolbar_contract as contract

STATEMENTS = {"denial": "toolbar-checkbox-connect-prompt-denied",
              "approval": "toolbar-checkbox-connect-prompt-approved",
              "reload": "toolbar-reopened-without-request"}


def main():
    class Parser(argparse.ArgumentParser):
        def error(self, message):
            raise contract.Refusal("attestation_invalid")
    parser = Parser(description=__doc__)
    parser.add_argument("--attestation-dir", required=True)
    parser.add_argument("--proof-id", required=True)
    parser.add_argument("--case", choices=sorted(contract.CASES), required=True)
    parser.add_argument("--observed", choices=sorted(STATEMENTS.values()), required=True)
    args = parser.parse_args()
    contract.require(contract.UUID.fullmatch(args.proof_id) and args.observed == STATEMENTS[args.case], "attestation_invalid")
    directory = contract.private_directory(args.attestation_dir)
    contract.require(contract.private_read(directory / "proof-id", 64) == args.proof_id.encode("ascii"), "attestation_invalid")
    interacted = args.case != "reload"
    value = {"schemaVersion": 1, "scope": "human-toolbar-attestation", "proofId": args.proof_id, "case": args.case,
        "toolbarOpened": True, "consentChecked": interacted, "connectClicked": interacted,
        "browserPromptSeen": interacted,
        "browserDecision": {"denial": "denied", "approval": "approved", "reload": "not_requested"}[args.case]}
    contract.validate_attestation(value, args.proof_id, args.case)
    encoded = json.dumps(value, separators=(",", ":")).encode("ascii")
    descriptor = os.open(directory / (args.case + ".json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        contract.require(os.write(descriptor, encoded) == len(encoded), "attestation_invalid")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    print(json.dumps({"scope": "human-toolbar-attestation-recorded", "proofId": args.proof_id, "case": args.case,
                      "observedBrowserProof": False}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({"scope": "human-toolbar-attestation-refused",
            "reason": error.reason if isinstance(error, contract.Refusal) else "attestation_invalid"}), file=sys.stderr)
        sys.exit(2)
