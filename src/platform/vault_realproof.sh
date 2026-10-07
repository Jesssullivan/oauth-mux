#!/usr/bin/env bash
set -euo pipefail
umask 077

# All executable paths are declared Bazel arguments. No host PATH discovery.
if [[ $# -lt 4 ]]; then exit 1; fi
driver=$1
dbus_session=$2
dbus_daemon=$3
keyring_daemon=$4
shift 4
for program in "$driver" "$dbus_session" "$dbus_daemon" "$keyring_daemon"; do
  [[ "$program" = /* ]] || program="$PWD/$program"
  [[ -x "$program" ]] || exit 1
done
[[ "$driver" = /* ]] || driver="$PWD/$driver"
[[ "$dbus_session" = /* ]] || dbus_session="$PWD/$dbus_session"
[[ "$dbus_daemon" = /* ]] || dbus_daemon="$PWD/$dbus_daemon"
[[ "$keyring_daemon" = /* ]] || keyring_daemon="$PWD/$keyring_daemon"

proof="$TEST_TMPDIR/native-vault"
mkdir -m 700 "$proof"
export XDG_RUNTIME_DIR="$proof/runtime"
export XDG_DATA_HOME="$proof/data" XDG_CONFIG_HOME="$proof/config" XDG_CACHE_HOME="$proof/cache"
mkdir -m 700 "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME"
unset DBUS_SESSION_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
export OMUX_ISOLATED_VAULT_PROOF=private-bus-private-xdg
export OMUX_PROOF_DRIVER="$driver" OMUX_PROOF_KEYRING="$keyring_daemon"
[[ "$XDG_RUNTIME_DIR" != *[\&\<\>\"\']* ]] || exit 1
# Bazel's private TEST_TMPDIR often exceeds sockaddr_un's path limit. A unique
# abstract socket retains EXTERNAL same-user authentication without a long path.
printf "%s\n" "<busconfig><type>session</type><listen>unix:abstract=omux-vault-proof-$$</listen><auth>EXTERNAL</auth><policy context=\"default\"><allow send_destination=\"*\"/><allow receive_sender=\"*\"/><allow own=\"*\"/></policy></busconfig>" > "$proof/session.conf"
exec "$dbus_session" --dbus-daemon="$dbus_daemon" --config-file="$proof/session.conf" -- "${BASH}" -c '
set -euo pipefail
keyring_pid=
cleanup() {
  if [[ -n "$keyring_pid" ]]; then
    kill "$keyring_pid" 2>/dev/null || true
    # TERM then KILL guarantees the wait cannot depend on daemon cooperation.
    kill -KILL "$keyring_pid" 2>/dev/null || true
    wait "$keyring_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
# Empty password is exclusive to this disposable keyring. Never in argv.
# The shell-held directory fd keeps the control socket inside TEST_TMPDIR while
# giving Linux a short socket pathname. The bridge still validates the actual
# XDG runtime path with its strict ancestor policy.
exec 9<"$XDG_RUNTIME_DIR"
control_directory="/proc/$BASHPID/fd/9/."
printf "\n" | "$OMUX_PROOF_KEYRING" --foreground --unlock --components=secrets --control-directory="$control_directory" >"$XDG_RUNTIME_DIR/keyring-startup" 2>/dev/null &
keyring_pid=$!
"$OMUX_PROOF_DRIVER" "$@"
' omux-isolated-vault "$@"
