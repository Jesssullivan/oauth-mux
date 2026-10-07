#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $# = 1 ]] || exit 1
driver=$1
[[ "$driver" = /* ]] || driver="$PWD/$driver"
export OMUX_PROOF_KEYCHAIN="$TEST_TMPDIR/omux-dedicated-proof.keychain-db"
exec "$driver"
