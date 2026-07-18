#!/usr/bin/env sh
# Synthetic source-only checks for the LaunchAgent environment boundary.

set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/omux-keepalive-containment.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
host_platform="$(/usr/bin/uname -s)"

fail() {
  printf 'smoke-keepalive-service-containment: %s\n' "$*" >&2
  exit 1
}

assert_contains_line() {
  grep -Fqx "$2" "$1" || fail "$3"
}

assert_absent() {
  if grep -Fq "$2" "$1"; then
    fail "$3"
  fi
}

assert_command_log() {
  printf '%s\n' "$1" >"$tmp/expected-command-log.txt"
  cmp -s "$tmp/expected-command-log.txt" "$command_log" ||
    fail "$2"
}

sed_escape_replacement() {
  printf '%s' "$1" | /usr/bin/sed 's/[\\&|]/\\&/g'
}

fixture_root="$tmp/fixture"
fixture_plist="$fixture_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl"
fixture_service="$fixture_root/scripts/keepalive-service.sh"
mkdir -p "$fixture_root/dist/launchd" "$fixture_root/dist/systemd" "$fixture_root/scripts"
cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" "$fixture_plist"
cp "$repo_root/dist/systemd/oauth-mux-keepalive.service.tmpl" \
  "$fixture_root/dist/systemd/oauth-mux-keepalive.service.tmpl"
cp "$repo_root/scripts/keepalive-service.sh" "$fixture_service"
chmod +x "$fixture_service"

fake_bin_dir="$tmp/fake-bin"
fake_omux="$fake_bin_dir/oauth-mux"
mkdir -p "$fake_bin_dir"
cat >"$fake_omux" <<'EOF'
#!/bin/sh
/usr/bin/env
EOF
chmod +x "$fake_omux"

fake_tools="$tmp/fake-tools"
command_log="$tmp/commands.log"
mutation_log="$tmp/mutations.log"
raw_sentinel="OMUX_RAW_LAUNCHCTL_SENTINEL_3024"
mkdir -p "$fake_tools"

cat >"$fake_tools/uname" <<'EOF'
#!/bin/sh
printf 'HostileOS\n'
EOF
cat >"$fake_tools/id" <<'EOF'
#!/bin/sh
printf '99999\n'
EOF
cat >"$fake_tools/launchctl" <<'EOF'
#!/bin/sh
printf 'PATH-resolved launchctl was invoked\n' >>"${OMUX_SMOKE_MUTATION_LOG:?}"
exit 99
EOF
cat >"$fake_tools/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl %s\n' "$*" >>"${OMUX_SMOKE_MUTATION_LOG:?}"
exit 97
EOF
cat >"$fake_tools/plutil" <<'EOF'
#!/bin/sh
exit 98
EOF
chmod +x \
  "$fake_tools/uname" \
  "$fake_tools/id" \
  "$fake_tools/launchctl" \
  "$fake_tools/systemctl" \
  "$fake_tools/plutil"

fixture_live_launchctl_refs="$(
  grep -Foc '/bin/launchctl' "$fixture_service" || true
)"
[ "$fixture_live_launchctl_refs" -gt 0 ] ||
  fail "render fixture contains no absolute /bin/launchctl reference"
fixture_poison_launchctl_sed="$(
  sed_escape_replacement "$fake_tools/launchctl"
)"
/usr/bin/sed \
  -e "s|/bin/launchctl|$fixture_poison_launchctl_sed|g" \
  "$fixture_service" >"$tmp/render-fixture-service.sh"
mv "$tmp/render-fixture-service.sh" "$fixture_service"
chmod +x "$fixture_service"
if grep -Fq '/bin/launchctl' "$fixture_service"; then
  fail "render fixture retained a live /bin/launchctl path"
fi
fixture_poison_launchctl_refs="$(
  grep -Foc "$fake_tools/launchctl" "$fixture_service" || true
)"
[ "$fixture_poison_launchctl_refs" = "$fixture_live_launchctl_refs" ] ||
  fail "render fixture did not rewrite every launchctl reference"

case "$host_platform" in
  Darwin)
    host_record="$(/usr/bin/id -P)"
    IFS=: read -r host_user host_password host_uid host_gid host_class host_change host_expire host_gecos host_home host_shell <<EOF
$host_record
EOF
    ;;
  Linux)
    host_uid="$(/usr/bin/id -u)"
    if [ -x /usr/bin/getent ]; then
      host_record="$(/usr/bin/getent passwd "$host_uid")"
    else
      host_record="$(/bin/getent passwd "$host_uid")"
    fi
    IFS=: read -r host_user host_password host_uid_record host_gid host_gecos host_home host_shell <<EOF
$host_record
EOF
    [ "$host_uid_record" = "$host_uid" ] ||
      fail "host account fixture uid did not match"
    ;;
  *) fail "unsupported smoke host $host_platform" ;;
esac

spoof_home="$tmp/spoofed-home"
spoof_user="spoofed-user"
mkdir -p "$spoof_home"
rendered="$tmp/rendered.txt"
HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render >"$rendered"

assert_absent "$rendered" '<key>EnvironmentVariables</key>' \
  "rendered plist retained EnvironmentVariables"
assert_absent "$rendered" '@OMUX_' "rendered output retained a template marker"

program_args="$tmp/program-args.txt"
sed -n '/^  <key>ProgramArguments<\/key>$/,/^  <\/array>$/p' "$rendered" |
  sed -n 's|^[[:space:]]*<string>\(.*\)</string>[[:space:]]*$|\1|p' \
    >"$program_args"
[ "$(wc -l <"$program_args" | tr -d ' ')" = "13" ] ||
  fail "rendered ProgramArguments did not contain the exact 13-argument wrapper"

set --
while IFS= read -r arg; do
  set -- "$@" "$arg"
done <"$program_args"

inherited_name="OMUX_SYNTHETIC_SECRET_SENTINEL"
inherited_value="omux-synthetic-secret-value-3024"
export OMUX_SYNTHETIC_SECRET_SENTINEL="$inherited_value"
child_env="$tmp/child-env.txt"
"$@" >"$child_env"
unset OMUX_SYNTHETIC_SECRET_SENTINEL

assert_absent "$child_env" "$inherited_name" \
  "env -i wrapper leaked the inherited sentinel name"
assert_absent "$child_env" "$inherited_value" \
  "env -i wrapper leaked the inherited sentinel value"
assert_contains_line "$child_env" "HOME=$host_home" "OS-derived HOME allowlist entry is absent"
assert_contains_line "$child_env" "USER=$host_user" "OS-derived USER allowlist entry is absent"
assert_absent "$child_env" "$spoof_home" "caller HOME reached the resident environment"
assert_absent "$child_env" "$spoof_user" "caller USER reached the resident environment"
assert_contains_line "$child_env" "PATH=/usr/bin:/bin:/usr/sbin:/sbin" \
  "fixed PATH allowlist entry is absent"
assert_contains_line "$child_env" "NO_COLOR=1" "NO_COLOR allowlist entry is absent"

expect_rejected() {
  er_name="$1"
  shift
  if "$@" >"$tmp/rejected.stdout" 2>"$tmp/rejected.stderr"; then
    fail "$er_name was accepted"
  fi
}

non_regular_omux_bin="$tmp/non-regular-omux-bin"
mkdir "$non_regular_omux_bin"
for non_regular_command in render verify install; do
  expect_rejected "non-regular OMUX_BIN for $non_regular_command" env \
    HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$non_regular_omux_bin" \
    PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" "$non_regular_command"
  grep -Fq 'OMUX_BIN must name a regular executable file' "$tmp/rejected.stderr" ||
    fail "$non_regular_command did not fail at explicit OMUX_BIN regular-file validation"
done

/usr/bin/env -u HOME -u USER OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render \
  >"$tmp/rendered-env-unset.txt"
cmp -s "$rendered" "$tmp/rendered-env-unset.txt" ||
  fail "render changed when caller HOME and USER were unset"

unsafe_sed_bin="$fake_bin_dir/oauth|mux"
unsafe_equals_bin="$fake_bin_dir/oauth=mux"
unsafe_soh_bin="$fake_bin_dir/oauth$(printf '\001')mux"
unsafe_tab_bin="$fake_bin_dir/oauth$(printf '\t')mux"
unsafe_del_bin="$fake_bin_dir/oauth$(printf '\177')mux"
unsafe_c1_bin="$fake_bin_dir/oauth$(printf '\302\200')mux"
safe_unicode_bin="$fake_bin_dir/oauth$(printf '\304\200')mux"
cp "$fake_omux" "$unsafe_sed_bin"
cp "$fake_omux" "$unsafe_equals_bin"
cp "$fake_omux" "$unsafe_soh_bin"
cp "$fake_omux" "$unsafe_tab_bin"
cp "$fake_omux" "$unsafe_del_bin"
cp "$fake_omux" "$unsafe_c1_bin"
cp "$fake_omux" "$safe_unicode_bin"
chmod +x \
  "$unsafe_sed_bin" \
  "$unsafe_equals_bin" \
  "$unsafe_soh_bin" \
  "$unsafe_tab_bin" \
  "$unsafe_del_bin" \
  "$unsafe_c1_bin" \
  "$safe_unicode_bin"
expect_rejected "executable path containing the sed delimiter" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_sed_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
expect_rejected "executable path containing an assignment delimiter" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_equals_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
expect_rejected "executable path containing SOH" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_soh_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
expect_rejected "executable path containing TAB" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_tab_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
expect_rejected "executable path containing DEL" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_del_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
expect_rejected "executable path containing C1" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$unsafe_c1_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$safe_unicode_bin" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render \
  >"$tmp/rendered-safe-unicode.txt"
grep -Fq "<string>$safe_unicode_bin</string>" "$tmp/rendered-safe-unicode.txt" ||
  fail "valid UTF-8 executable path was rejected as a control-byte path"

cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" "$fixture_plist"
awk '
  { print }
  /<string>NO_COLOR=1<\/string>/ {
    print "    <string>EXTRA=value</string>"
  }
' "$fixture_plist" >"$tmp/unknown-assignment.plist"
mv "$tmp/unknown-assignment.plist" "$fixture_plist"
expect_rejected "noncanonical ProgramArguments assignment" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render

cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" "$fixture_plist"
sed 's|<string>NO_COLOR=1</string>|<string>@OMUX_UNKNOWN@</string>|' \
  "$fixture_plist" >"$tmp/unresolved-marker.plist"
mv "$tmp/unresolved-marker.plist" "$fixture_plist"
expect_rejected "unresolved template marker" env \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render

set_plist_insertion() {
  spi_insertion="$1"
  printf '%s\n' "$spi_insertion" >"$tmp/insertion.txt"
  awk -v insertion_file="$tmp/insertion.txt" '
    $0 == "</dict>" {
      while ((getline insertion < insertion_file) > 0) print insertion
      close(insertion_file)
    }
    { print }
  ' "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" \
    >"$tmp/adversarial.plist"
  mv "$tmp/adversarial.plist" "$fixture_plist"
}

expect_adversarial_plist_rejected() {
  eap_name="$1"
  expect_rejected "$eap_name" env \
    HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
    PATH="$fake_tools:/usr/bin:/bin" "$fixture_service" render
}

set_plist_insertion '  <key>Program</key>
  <string>/bin/false</string>'
expect_adversarial_plist_rejected "top-level Program override"

set_plist_insertion '  <key>EnvironmentVariables</key>
  <dict><key>FOO</key><string>bar</string></dict>'
expect_adversarial_plist_rejected "top-level EnvironmentVariables override"

set_plist_insertion '    <key>ProgramArguments</key>
    <array><string>/bin/false</string></array>'
if [ "$host_platform" = "Darwin" ]; then
  effective_argv0="$(
    /usr/bin/plutil -extract ProgramArguments.0 raw -o - -- "$fixture_plist"
  )" || fail "/usr/bin/plutil could not resolve the duplicate argv fixture"
  [ "$effective_argv0" = "/bin/false" ] ||
    fail "/usr/bin/plutil did not select the later duplicate argv"
fi
expect_adversarial_plist_rejected "differently indented effective argv override"

set_plist_insertion '	<key>ProgramArguments</key>
	<array><string>/bin/false</string></array>'
expect_adversarial_plist_rejected "tab-indented duplicate ProgramArguments"

set_plist_insertion '  <key>Program&#65;rguments</key>
  <array><string>/bin/false</string></array>'
if [ "$host_platform" = "Darwin" ]; then
  entity_argv0="$(
    /usr/bin/plutil -extract ProgramArguments.0 raw -o - -- "$fixture_plist"
  )" || fail "/usr/bin/plutil could not resolve the entity-key argv fixture"
  [ "$entity_argv0" = "/bin/false" ] ||
    fail "/usr/bin/plutil did not decode the entity-key argv override"
fi
expect_adversarial_plist_rejected "entity-encoded duplicate ProgramArguments"

set_plist_insertion '  <key>Progr&#97;m</key>
  <string>/bin/false</string>'
expect_adversarial_plist_rejected "entity-encoded Program key"

set_plist_insertion '  <key>Environment&#86;ariables</key>
  <dict><key>FOO</key><string>bar</string></dict>'
expect_adversarial_plist_rejected "entity-encoded EnvironmentVariables key"

set_plist_insertion '  <key>StandardOutPath</key>
  <string>/tmp/override</string>'
expect_adversarial_plist_rejected "duplicate top-level value override"

cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" "$fixture_plist"
sed 's|<integer>300</integer>|<integer>1</integer>|' \
  "$fixture_plist" >"$tmp/override-value.plist"
mv "$tmp/override-value.plist" "$fixture_plist"
expect_adversarial_plist_rejected "noncanonical top-level value"

cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" "$fixture_plist"

export OMUX_SMOKE_COMMAND_LOG="$command_log"
export OMUX_SMOKE_MUTATION_LOG="$mutation_log"
export OMUX_SMOKE_RAW_SENTINEL="$raw_sentinel"

help_output="$tmp/help.txt"
/usr/bin/env -u HOME -u USER PATH="$fake_tools:/usr/bin:/bin" \
  "$fixture_service" help >"$help_output"
grep -Fq 'usage: keepalive-service.sh' "$help_output" ||
  fail "help failed with HOME and USER unset"

# A disposable Linux fixture proves identity derivation without any FHS
# identity tool. PATH contains hostile lookalikes; only the explicit
# /run/current-system/sw candidate rewrites may run.
non_fhs_root="$tmp/non-fhs-linux-fixture"
non_fhs_service="$non_fhs_root/scripts/keepalive-service.sh"
non_fhs_tools="$tmp/non-fhs-linux-tools"
non_fhs_missing="$tmp/non-fhs-linux-missing"
non_fhs_home="$tmp/non-fhs-linux-home"
non_fhs_user="nix-user"
non_fhs_uid="5252"
mkdir -p \
  "$non_fhs_root/dist/launchd" \
  "$non_fhs_root/dist/systemd" \
  "$non_fhs_root/scripts" \
  "$non_fhs_tools" \
  "$non_fhs_missing" \
  "$non_fhs_home"
cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" \
  "$non_fhs_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl"
cp "$repo_root/dist/systemd/oauth-mux-keepalive.service.tmpl" \
  "$non_fhs_root/dist/systemd/oauth-mux-keepalive.service.tmpl"

cat >"$non_fhs_tools/uname" <<'EOF'
#!/bin/sh
printf 'Linux\n'
EOF
cat >"$non_fhs_tools/id" <<'EOF'
#!/bin/sh
[ "${1:-}" = "-u" ] || exit 64
printf '%s\n' "${OMUX_SMOKE_DERIVED_UID:?}"
EOF
cat >"$non_fhs_tools/getent" <<'EOF'
#!/bin/sh
[ "${1:-}" = "passwd" ] || exit 64
[ "${2:-}" = "${OMUX_SMOKE_DERIVED_UID:?}" ] || exit 65
if [ "${OMUX_SMOKE_ACCOUNT_RECORD+x}" = "x" ]; then
  printf '%s\n' "$OMUX_SMOKE_ACCOUNT_RECORD"
  exit 0
fi
printf '%s:*:%s:20:Managed:%s:/bin/sh\n' \
  "${OMUX_SMOKE_DERIVED_USER:?}" \
  "${OMUX_SMOKE_DERIVED_UID:?}" \
  "${OMUX_SMOKE_DERIVED_HOME:?}"
EOF
cat >"$non_fhs_tools/od" <<'EOF'
#!/bin/sh
exec /usr/bin/od "$@"
EOF
cat >"$non_fhs_tools/awk" <<'EOF'
#!/bin/sh
exec /usr/bin/awk "$@"
EOF
chmod +x \
  "$non_fhs_tools/uname" \
  "$non_fhs_tools/id" \
  "$non_fhs_tools/getent" \
  "$non_fhs_tools/od" \
  "$non_fhs_tools/awk"

non_fhs_uname_sed="$(sed_escape_replacement "$non_fhs_tools/uname")"
non_fhs_id_sed="$(sed_escape_replacement "$non_fhs_tools/id")"
non_fhs_getent_sed="$(sed_escape_replacement "$non_fhs_tools/getent")"
non_fhs_od_sed="$(sed_escape_replacement "$non_fhs_tools/od")"
non_fhs_awk_sed="$(sed_escape_replacement "$non_fhs_tools/awk")"
missing_uname_sed="$(sed_escape_replacement "$non_fhs_missing/uname")"
missing_id_sed="$(sed_escape_replacement "$non_fhs_missing/id")"
missing_getent_sed="$(sed_escape_replacement "$non_fhs_missing/getent")"
missing_od_sed="$(sed_escape_replacement "$non_fhs_missing/od")"
missing_awk_sed="$(sed_escape_replacement "$non_fhs_missing/awk")"

/usr/bin/sed \
  -e "s|/run/current-system/sw/bin/uname|$non_fhs_uname_sed|g" \
  -e "s|/nix/var/nix/profiles/default/bin/uname|$missing_uname_sed|g" \
  -e "s|/usr/bin/uname|$missing_uname_sed|g" \
  -e "s|/bin/uname|$missing_uname_sed|g" \
  -e "s|/run/current-system/sw/bin/id|$non_fhs_id_sed|g" \
  -e "s|/nix/var/nix/profiles/default/bin/id|$missing_id_sed|g" \
  -e "s|/usr/bin/id|$missing_id_sed|g" \
  -e "s|/bin/id|$missing_id_sed|g" \
  -e "s|/run/current-system/sw/bin/getent|$non_fhs_getent_sed|g" \
  -e "s|/nix/var/nix/profiles/default/bin/getent|$missing_getent_sed|g" \
  -e "s|/usr/bin/getent|$missing_getent_sed|g" \
  -e "s|/bin/getent|$missing_getent_sed|g" \
  -e "s|/run/current-system/sw/bin/od|$non_fhs_od_sed|g" \
  -e "s|/nix/var/nix/profiles/default/bin/od|$missing_od_sed|g" \
  -e "s|/usr/bin/od|$missing_od_sed|g" \
  -e "s|/bin/od|$missing_od_sed|g" \
  -e "s|/run/current-system/sw/bin/awk|$non_fhs_awk_sed|g" \
  -e "s|/nix/var/nix/profiles/default/bin/awk|$missing_awk_sed|g" \
  -e "s|/usr/bin/awk|$missing_awk_sed|g" \
  -e "s|/bin/awk|$missing_awk_sed|g" \
  "$repo_root/scripts/keepalive-service.sh" >"$non_fhs_service"
chmod +x "$non_fhs_service"

OMUX_SMOKE_DERIVED_HOME="$non_fhs_home" \
  OMUX_SMOKE_DERIVED_USER="$non_fhs_user" \
  OMUX_SMOKE_DERIVED_UID="$non_fhs_uid" \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$non_fhs_service" render \
  >"$tmp/non-fhs-rendered.txt"
grep -Fq "<string>HOME=$non_fhs_home</string>" "$tmp/non-fhs-rendered.txt" ||
  fail "trusted non-FHS Linux identity did not supply HOME"
grep -Fq "<string>USER=$non_fhs_user</string>" "$tmp/non-fhs-rendered.txt" ||
  fail "trusted non-FHS Linux identity did not supply USER"
assert_absent "$tmp/non-fhs-rendered.txt" "$spoof_home" \
  "caller HOME overrode trusted non-FHS Linux identity"
assert_absent "$tmp/non-fhs-rendered.txt" "$spoof_user" \
  "caller USER overrode trusted non-FHS Linux identity"

expect_non_fhs_record_rejected() {
  enfhr_name="$1"
  enfhr_record="$2"
  expect_rejected "$enfhr_name" env \
    OMUX_SMOKE_ACCOUNT_RECORD="$enfhr_record" \
    OMUX_SMOKE_DERIVED_HOME="$non_fhs_home" \
    OMUX_SMOKE_DERIVED_USER="$non_fhs_user" \
    OMUX_SMOKE_DERIVED_UID="$non_fhs_uid" \
    HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
    PATH="$fake_tools:/usr/bin:/bin" "$non_fhs_service" render
}

expect_non_fhs_record_rejected \
  "non-FHS getent record with a surplus field" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:$non_fhs_home:/bin/sh:surplus"
expect_non_fhs_record_rejected \
  "non-FHS getent record with a missing field" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:$non_fhs_home"
non_fhs_duplicate_record="$(
  printf '%s:*:%s:20:Managed:%s:/bin/sh\n' \
    "$non_fhs_user" "$non_fhs_uid" "$non_fhs_home"
  printf '%s-duplicate:*:%s:20:Managed:%s:/bin/sh\n' \
    "$non_fhs_user" "$non_fhs_uid" "$non_fhs_home"
)"
expect_non_fhs_record_rejected \
  "non-FHS getent lookup with duplicate uid records" \
  "$non_fhs_duplicate_record"
expect_non_fhs_record_rejected \
  "non-FHS getent record with an unsafe user" \
  "unsafe user:*:$non_fhs_uid:20:Managed:$non_fhs_home:/bin/sh"
expect_non_fhs_record_rejected \
  "non-FHS getent record with an unsafe home" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:relative/home:/bin/sh"

# Minimal Linux without getent falls back to a fixed account database using
# shell builtins. The test rewrites only the fixed /etc/passwd path inside its
# disposable copy.
minimal_passwd="$tmp/minimal-linux-passwd"
minimal_service="$non_fhs_root/scripts/keepalive-service-minimal.sh"
printf '%s:*:%s:20:Managed:%s:/bin/sh\n' \
  "$non_fhs_user" "$non_fhs_uid" "$non_fhs_home" >"$minimal_passwd"
minimal_passwd_sed="$(sed_escape_replacement "$minimal_passwd")"
/usr/bin/sed \
  -e "s|$non_fhs_getent_sed|$missing_getent_sed|g" \
  -e "s|/etc/passwd|$minimal_passwd_sed|g" \
  "$non_fhs_service" >"$minimal_service"
chmod +x "$minimal_service"

OMUX_SMOKE_DERIVED_HOME="$non_fhs_home" \
  OMUX_SMOKE_DERIVED_USER="$non_fhs_user" \
  OMUX_SMOKE_DERIVED_UID="$non_fhs_uid" \
  HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$minimal_service" render \
  >"$tmp/minimal-linux-rendered.txt"
grep -Fq "<string>HOME=$non_fhs_home</string>" "$tmp/minimal-linux-rendered.txt" ||
  fail "minimal Linux passwd fallback did not supply HOME"
grep -Fq "<string>USER=$non_fhs_user</string>" "$tmp/minimal-linux-rendered.txt" ||
  fail "minimal Linux passwd fallback did not supply USER"

expect_minimal_passwd_rejected() {
  empr_name="$1"
  empr_records="$2"
  printf '%s\n' "$empr_records" >"$minimal_passwd"
  expect_rejected "$empr_name" env \
    OMUX_SMOKE_DERIVED_HOME="$non_fhs_home" \
    OMUX_SMOKE_DERIVED_USER="$non_fhs_user" \
    OMUX_SMOKE_DERIVED_UID="$non_fhs_uid" \
    HOME="$spoof_home" USER="$spoof_user" OMUX_BIN="$fake_omux" \
    PATH="$fake_tools:/usr/bin:/bin" "$minimal_service" render
}

expect_minimal_passwd_rejected \
  "minimal Linux passwd record with a surplus field" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:$non_fhs_home:/bin/sh:surplus"
expect_minimal_passwd_rejected \
  "minimal Linux passwd record with a missing field" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:$non_fhs_home"
minimal_duplicate_record="$(
  printf '%s:*:%s:20:Managed:%s:/bin/sh\n' \
    "$non_fhs_user" "$non_fhs_uid" "$non_fhs_home"
  printf '%s-duplicate:*:%s:20:Managed:%s:/bin/sh\n' \
    "$non_fhs_user" "$non_fhs_uid" "$non_fhs_home"
)"
expect_minimal_passwd_rejected \
  "minimal Linux passwd database with duplicate uid records" \
  "$minimal_duplicate_record"
expect_minimal_passwd_rejected \
  "minimal Linux passwd record with an unsafe user" \
  "unsafe user:*:$non_fhs_uid:20:Managed:$non_fhs_home:/bin/sh"
expect_minimal_passwd_rejected \
  "minimal Linux passwd record with an unsafe home" \
  "$non_fhs_user:*:$non_fhs_uid:20:Managed:relative/home:/bin/sh"

fake_system="$tmp/fake-system"
lifecycle_root="$tmp/lifecycle-fixture"
lifecycle_service="$lifecycle_root/scripts/keepalive-service.sh"
managed_home="$tmp/managed-home"
managed_user="managed-user"
managed_uid="4242"
mkdir -p \
  "$fake_system" \
  "$lifecycle_root/dist/launchd" \
  "$lifecycle_root/dist/systemd" \
  "$lifecycle_root/scripts" \
  "$managed_home"
cp "$repo_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl" \
  "$lifecycle_root/dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl"
cp "$repo_root/dist/systemd/oauth-mux-keepalive.service.tmpl" \
  "$lifecycle_root/dist/systemd/oauth-mux-keepalive.service.tmpl"

cat >"$fake_system/uname" <<'EOF'
#!/bin/sh
printf 'Darwin\n'
EOF
cat >"$fake_system/id" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -u) printf '%s\n' "${OMUX_SMOKE_DERIVED_UID:?}" ;;
  -P)
    printf '%s:*:%s:20::0:0:Managed:%s:/bin/sh\n' \
      "${OMUX_SMOKE_DERIVED_USER:?}" \
      "${OMUX_SMOKE_DERIVED_UID:?}" \
      "${OMUX_SMOKE_DERIVED_HOME:?}"
    ;;
  *) exit 64 ;;
esac
EOF
cat >"$fake_system/getent" <<'EOF'
#!/bin/sh
[ "${1:-}" = "passwd" ] || exit 64
[ "${2:-}" = "${OMUX_SMOKE_DERIVED_UID:?}" ] || exit 65
printf '%s:*:%s:20:Managed:%s:/bin/sh\n' \
  "${OMUX_SMOKE_DERIVED_USER:?}" \
  "${OMUX_SMOKE_DERIVED_UID:?}" \
  "${OMUX_SMOKE_DERIVED_HOME:?}"
EOF
cat >"$fake_system/plutil" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -convert) cat ;;
  -lint) exit 0 ;;
  *) exit 64 ;;
esac
EOF
cat >"$fake_system/launchctl" <<'EOF'
#!/bin/sh
: "${OMUX_SMOKE_COMMAND_LOG:?}"
printf 'launchctl argc=%s' "$#" >>"$OMUX_SMOKE_COMMAND_LOG"
lc_index=1
for lc_arg in "$@"; do
  printf ' arg%s=%s' "$lc_index" "$lc_arg" >>"$OMUX_SMOKE_COMMAND_LOG"
  lc_index=$((lc_index + 1))
done
printf '\n' >>"$OMUX_SMOKE_COMMAND_LOG"
case "${1:-}" in
  print)
    printf '%s\n' "${OMUX_SMOKE_RAW_SENTINEL:?}"
    case "${OMUX_SMOKE_LAUNCHCTL_STATE:-loaded}" in
      absent) exit 113 ;;
      print_failure) exit 70 ;;
      *) exit 0 ;;
    esac
    ;;
  bootout)
    printf 'launchctl bootout\n' >>"${OMUX_SMOKE_MUTATION_LOG:?}"
    [ "${OMUX_SMOKE_LAUNCHCTL_STATE:-loaded}" != "bootout_failure" ]
    ;;
  bootstrap)
    printf 'launchctl bootstrap\n' >>"${OMUX_SMOKE_MUTATION_LOG:?}"
    exit 0
    ;;
  *)
    printf 'launchctl unexpected\n' >>"${OMUX_SMOKE_MUTATION_LOG:?}"
    exit 97
    ;;
esac
EOF
chmod +x \
  "$fake_system/uname" \
  "$fake_system/id" \
  "$fake_system/getent" \
  "$fake_system/plutil" \
  "$fake_system/launchctl"

# The production script keeps OS identity tools absolute. Redirect those
# absolute paths, including /bin/launchctl, only inside this disposable fixture
# so Darwin lifecycle logic can use a temp account and fake service manager.
fake_uname_sed="$(sed_escape_replacement "$fake_system/uname")"
fake_id_sed="$(sed_escape_replacement "$fake_system/id")"
fake_getent_sed="$(sed_escape_replacement "$fake_system/getent")"
fake_plutil_sed="$(sed_escape_replacement "$fake_system/plutil")"
fake_launchctl_sed="$(sed_escape_replacement "$fake_system/launchctl")"
source_launchctl_refs="$(
  grep -Foc '/bin/launchctl' "$repo_root/scripts/keepalive-service.sh" || true
)"
[ "$source_launchctl_refs" -gt 0 ] ||
  fail "production script contains no absolute /bin/launchctl reference"
sed \
  -e "s|/usr/bin/uname|$fake_uname_sed|g" \
  -e "s|/bin/uname|$fake_uname_sed|g" \
  -e "s|/usr/bin/id|$fake_id_sed|g" \
  -e "s|/bin/id|$fake_id_sed|g" \
  -e "s|/usr/bin/getent|$fake_getent_sed|g" \
  -e "s|/bin/getent|$fake_getent_sed|g" \
  -e "s|/usr/bin/plutil|$fake_plutil_sed|g" \
  -e "s|/bin/launchctl|$fake_launchctl_sed|g" \
  "$repo_root/scripts/keepalive-service.sh" >"$lifecycle_service"
chmod +x "$lifecycle_service"
if grep -Fq '/bin/launchctl' "$lifecycle_service"; then
  fail "disposable lifecycle fixture retained a live /bin/launchctl path"
fi
fixture_launchctl_refs="$(
  grep -Foc "$fake_system/launchctl" "$lifecycle_service" || true
)"
[ "$fixture_launchctl_refs" = "$source_launchctl_refs" ] ||
  fail "disposable lifecycle fixture did not rewrite every launchctl reference"

export OMUX_SMOKE_DERIVED_HOME="$managed_home"
export OMUX_SMOKE_DERIVED_USER="$managed_user"
export OMUX_SMOKE_DERIVED_UID="$managed_uid"

expected_print="launchctl argc=2 arg1=print arg2=gui/$managed_uid/dev.xoxd.omux.keepalive"
expected_bootout="launchctl argc=3 arg1=bootout arg2=gui/$managed_uid arg3=$managed_home/Library/LaunchAgents/dev.xoxd.omux.keepalive.plist"
expected_bootstrap="launchctl argc=3 arg1=bootstrap arg2=gui/$managed_uid arg3=$managed_home/Library/LaunchAgents/dev.xoxd.omux.keepalive.plist"

loaded_status="$tmp/status-loaded.txt"
/usr/bin/env -u HOME -u USER \
  OMUX_SMOKE_COMMAND_LOG="$command_log" \
  OMUX_SMOKE_MUTATION_LOG="$mutation_log" \
  OMUX_SMOKE_RAW_SENTINEL="$raw_sentinel" \
  OMUX_SMOKE_DERIVED_HOME="$managed_home" \
  OMUX_SMOKE_DERIVED_USER="$managed_user" \
  OMUX_SMOKE_DERIVED_UID="$managed_uid" \
  PATH="$fake_tools:/usr/bin:/bin" "$lifecycle_service" status >"$loaded_status"
printf 'service_label=dev.xoxd.omux.keepalive\nservice_loaded=true\n' \
  >"$tmp/expected-loaded.txt"
cmp -s "$tmp/expected-loaded.txt" "$loaded_status" ||
  fail "Darwin loaded status was not the fixed allowlisted shape"
assert_absent "$loaded_status" "$raw_sentinel" \
  "Darwin status emitted raw launchctl bytes"

unloaded_status="$tmp/status-unloaded.txt"
OMUX_SMOKE_LAUNCHCTL_STATE=absent \
  /usr/bin/env -u HOME -u USER PATH="$fake_tools:/usr/bin:/bin" \
  "$lifecycle_service" status >"$unloaded_status"
printf 'service_label=dev.xoxd.omux.keepalive\nservice_loaded=false\n' \
  >"$tmp/expected-unloaded.txt"
cmp -s "$tmp/expected-unloaded.txt" "$unloaded_status" ||
  fail "Darwin unloaded status was not the fixed allowlisted shape"
assert_absent "$unloaded_status" "$raw_sentinel" \
  "Darwin unloaded status emitted raw launchctl bytes"

expect_rejected "launchctl status inspection failure" env \
  OMUX_SMOKE_LAUNCHCTL_STATE=print_failure \
  PATH="$fake_tools:/usr/bin:/bin" "$lifecycle_service" status
assert_absent "$tmp/rejected.stdout" "service_loaded=false" \
  "launchctl inspection failure was reported as an absent job"

[ ! -s "$mutation_log" ] || fail "synthetic smoke attempted a service mutation"
[ "$(wc -l <"$command_log" | tr -d ' ')" = "3" ] ||
  fail "synthetic smoke made an unexpected service-manager call"
assert_command_log "$expected_print
$expected_print
$expected_print" \
  "Darwin status did not use the exact launchctl print domain and label"
if grep -Eq '(^| )(bootstrap|bootout|kickstart|install|uninstall|enable|disable|restart|start|stop|daemon-reload)( |$)' "$command_log"; then
  fail "synthetic smoke invoked a service mutation command"
fi

managed_plist_dir="$managed_home/Library/LaunchAgents"
managed_plist="$managed_plist_dir/dev.xoxd.omux.keepalive.plist"
mkdir -p "$managed_plist_dir"
printf 'original plist sentinel\n' >"$managed_plist"

: >"$command_log"
: >"$mutation_log"
expect_rejected "install with loaded-job bootout failure" env \
  OMUX_SMOKE_LAUNCHCTL_STATE=bootout_failure \
  OMUX_BIN="$fake_omux" PATH="$fake_tools:/usr/bin:/bin" \
  "$lifecycle_service" install
grep -Fqx 'original plist sentinel' "$managed_plist" ||
  fail "failed install replaced the existing plist"
assert_absent "$tmp/rejected.stdout" "installed and loaded:" \
  "failed install reported success"
if /usr/bin/find "$managed_plist_dir" -name '.dev.xoxd.omux.keepalive.plist.tmp.*' \
  -print | grep -q .; then
  fail "failed install left a rendered temporary plist"
fi
assert_command_log "$expected_print
$expected_bootout" \
  "failed install did not use exact launchctl print/bootout arguments"

: >"$command_log"
: >"$mutation_log"
expect_rejected "uninstall with loaded-job bootout failure" env \
  OMUX_SMOKE_LAUNCHCTL_STATE=bootout_failure \
  PATH="$fake_tools:/usr/bin:/bin" "$lifecycle_service" uninstall
[ -f "$managed_plist" ] ||
  fail "failed uninstall removed the plist"
assert_absent "$tmp/rejected.stdout" "removed " \
  "failed uninstall reported success"
assert_command_log "$expected_print
$expected_bootout" \
  "failed uninstall did not use exact launchctl print/bootout arguments"

: >"$command_log"
: >"$mutation_log"
OMUX_SMOKE_LAUNCHCTL_STATE=absent OMUX_BIN="$fake_omux" \
  PATH="$fake_tools:/usr/bin:/bin" "$lifecycle_service" install \
  >"$tmp/install-absent.stdout"
grep -Fq "installed and loaded: $managed_plist" "$tmp/install-absent.stdout" ||
  fail "install did not report success after an absent-job result"
grep -Fqx 'launchctl bootstrap' "$mutation_log" ||
  fail "absent-job install did not bootstrap the rendered plist"
if grep -Fqx 'launchctl bootout' "$mutation_log"; then
  fail "absent-job install attempted bootout"
fi
assert_command_log "$expected_print
$expected_bootstrap" \
  "absent-job install did not use exact launchctl print/bootstrap arguments"

: >"$command_log"
: >"$mutation_log"
OMUX_SMOKE_LAUNCHCTL_STATE=absent \
  PATH="$fake_tools:/usr/bin:/bin" "$lifecycle_service" uninstall \
  >"$tmp/uninstall-absent.stdout"
[ ! -e "$managed_plist" ] ||
  fail "absent-job uninstall did not remove the plist"
grep -Fq "removed $managed_plist" "$tmp/uninstall-absent.stdout" ||
  fail "absent-job uninstall did not report removal"
[ ! -s "$mutation_log" ] ||
  fail "absent-job uninstall attempted a launchctl mutation"
assert_command_log "$expected_print" \
  "absent-job uninstall did not use the exact launchctl print argument"

printf '%s\n' \
  'keepalive service containment smoke passed (source-only; fake service manager only)'
