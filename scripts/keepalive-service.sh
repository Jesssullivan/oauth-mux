#!/usr/bin/env sh
# Operator-explicit management of the oauth-mux keepalive user service
# (TIN-1830). POSIX sh; nothing here runs at build or package time.
set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

label="dev.xoxd.omux.keepalive"
unit_name="oauth-mux-keepalive.service"
plist_template="$repo_root/dist/launchd/${label}.plist.tmpl"
systemd_template="$repo_root/dist/systemd/${unit_name}.tmpl"
render_home=""
render_user=""
render_uid=""
plist_target=""
systemd_target=""
log_dir=""
platform=""
launchctl_absent_status=113
nl='
'
cr="$(printf '\r')"

usage() {
  cat <<'EOF'
usage: keepalive-service.sh <install|uninstall|status|render|verify>

Operator-explicit management of the oauth-mux keepalive user service
(launchd LaunchAgent on macOS, systemd user unit on Linux). Nothing here
runs automatically at build or package time.

  install    render unit with resolved binary path, lint, place, load/enable
  uninstall  unload/disable and remove the placed unit file
  status     show fixed service state fields (plus journal lines on Linux)
  render     print rendered unit(s) to stdout without installing
  verify     offline static checks (lint, correct verb, credential-free)

env: OMUX_BIN=/abs/path/to/oauth-mux overrides binary resolution and must name
     a regular executable file.
EOF
}

fail() { printf 'keepalive-service: %s\n' "$1" >&2; exit 1; }

optional_absolute_tool() {
  for at_candidate in "$@"; do
    if [ -f "$at_candidate" ] && [ -x "$at_candidate" ]; then
      printf '%s\n' "$at_candidate"
      return 0
    fi
  done
  return 1
}

absolute_tool() {
  optional_absolute_tool "$@" && return 0
  fail "required system tool is unavailable"
}

contains_unsafe_control() { # $1=value
  cuc_od="$(absolute_tool \
    /usr/bin/od /bin/od \
    /run/current-system/sw/bin/od \
    /nix/var/nix/profiles/default/bin/od)"
  cuc_awk="$(absolute_tool \
    /usr/bin/awk /bin/awk \
    /run/current-system/sw/bin/awk \
    /nix/var/nix/profiles/default/bin/awk)"
  printf '%s' "$1" |
    LC_ALL=C "$cuc_od" -An -v -tu1 |
    LC_ALL=C "$cuc_awk" '
      {
        for (field = 1; field <= NF; field++) {
          bytes[++count] = $field + 0
        }
      }
      END {
        if (count == 0) exit 2
        unsafe = 0
        pos = 1
        while (pos <= count) {
          first = bytes[pos]
          if (first <= 31 || first == 127) {
            unsafe = 1
            break
          }
          if (first <= 126) {
            pos++
            continue
          }
          if (first >= 194 && first <= 223) {
            if (pos + 1 > count ||
                bytes[pos + 1] < 128 || bytes[pos + 1] > 191) {
              unsafe = 1
              break
            }
            codepoint = (first - 192) * 64 + (bytes[pos + 1] - 128)
            if (codepoint >= 128 && codepoint <= 159) {
              unsafe = 1
              break
            }
            pos += 2
            continue
          }
          if (first >= 224 && first <= 239) {
            if (pos + 2 > count ||
                bytes[pos + 1] < 128 || bytes[pos + 1] > 191 ||
                bytes[pos + 2] < 128 || bytes[pos + 2] > 191 ||
                (first == 224 && bytes[pos + 1] < 160) ||
                (first == 237 && bytes[pos + 1] > 159)) {
              unsafe = 1
              break
            }
            pos += 3
            continue
          }
          if (first >= 240 && first <= 244) {
            if (pos + 3 > count ||
                bytes[pos + 1] < 128 || bytes[pos + 1] > 191 ||
                bytes[pos + 2] < 128 || bytes[pos + 2] > 191 ||
                bytes[pos + 3] < 128 || bytes[pos + 3] > 191 ||
                (first == 240 && bytes[pos + 1] < 144) ||
                (first == 244 && bytes[pos + 1] > 143)) {
              unsafe = 1
              break
            }
            pos += 4
            continue
          }
          unsafe = 1
          break
        }
        exit unsafe ? 0 : 1
      }
    '
}

validate_render_value() { # $1=name, $2=value
  [ -n "$2" ] || fail "$1 must not be empty"
  if contains_unsafe_control "$2"; then
    fail "$1 contains a control character or invalid UTF-8"
  else
    vrv_control_status=$?
    [ "$vrv_control_status" -eq 1 ] ||
      fail "could not validate $1 for control characters"
  fi
  case "$2" in
    *'@OMUX_'*) fail "$1 contains an unresolved template marker" ;;
    *'|'* | *'&'* | *'<'* | *'>'* | *'--'* | *"\\"* | *"$nl"* | *"$cr"*)
      fail "$1 contains an XML or sed metacharacter"
      ;;
  esac
}

validate_home() {
  validate_render_value "HOME" "$1"
  case "$1" in
    /*) ;;
    *) fail "HOME must be an absolute path" ;;
  esac
}

validate_user() {
  validate_render_value "USER" "$1"
  case "$1" in
    -* | *[!A-Za-z0-9._-]*) fail "USER contains an unsafe character" ;;
  esac
}

validate_uid() {
  case "$1" in
    '' | *[!0-9]*) fail "OS uid is not numeric" ;;
  esac
}

parse_linux_account_record() { # $1=one passwd record; sets plar_user/uid/home
  plar_record="$1"
  case "$plar_record" in
    '' | *"$nl"* | *"$cr"*) return 1 ;;
  esac

  # Appending a marker makes POSIX read distinguish exactly seven fields from
  # both missing fields and surplus delimiters (including an empty eighth).
  if ! IFS=: read -r \
    plar_user _plar_password plar_uid _plar_gid _plar_gecos plar_home \
    _plar_shell plar_end <<EOF
$plar_record:__OMUX_ACCOUNT_RECORD_END__
EOF
  then
    return 1
  fi
  [ "$plar_end" = "__OMUX_ACCOUNT_RECORD_END__" ] || return 1

  validate_uid "$plar_uid"
  validate_user "$plar_user"
  validate_home "$plar_home"
}

validate_executable_path() {
  validate_render_value "oauth-mux executable path" "$1"
  case "$1" in
    /*) ;;
    *) fail "oauth-mux executable path must be absolute" ;;
  esac
  case "$1" in
    *'='*) fail "oauth-mux executable path must not contain '='" ;;
  esac
}

detect_platform() {
  dp_uname="$(absolute_tool \
    /usr/bin/uname /bin/uname \
    /run/current-system/sw/bin/uname \
    /nix/var/nix/profiles/default/bin/uname)"
  platform="$("$dp_uname" -s)" ||
    fail "could not determine the operating system"
}

os_uid() {
  ou_id="$(absolute_tool \
    /usr/bin/id /bin/id \
    /run/current-system/sw/bin/id \
    /nix/var/nix/profiles/default/bin/id)"
  ou_uid="$("$ou_id" -u)" || fail "could not resolve the OS uid"
  validate_uid "$ou_uid"
  printf '%s\n' "$ou_uid"
}

derive_render_identity() {
  dri_id="$(absolute_tool \
    /usr/bin/id /bin/id \
    /run/current-system/sw/bin/id \
    /nix/var/nix/profiles/default/bin/id)"
  render_uid="$("$dri_id" -u)" || fail "could not resolve the OS uid"
  validate_uid "$render_uid"

  case "$platform" in
    Linux)
      if dri_getent="$(optional_absolute_tool \
        /usr/bin/getent /bin/getent \
        /run/current-system/sw/bin/getent \
        /nix/var/nix/profiles/default/bin/getent)"; then
        dri_record="$("$dri_getent" passwd "$render_uid")" ||
          fail "could not resolve the OS account record"
        parse_linux_account_record "$dri_record" ||
          fail "OS account lookup returned a malformed or ambiguous record"
        render_user="$plar_user"
        dri_uid="$plar_uid"
        render_home="$plar_home"
      else
        [ -f /etc/passwd ] && [ -r /etc/passwd ] ||
          fail "no trusted Linux account database is available"
        dri_found=0
        while IFS= read -r dri_record || [ -n "$dri_record" ]; do
          parse_linux_account_record "$dri_record" ||
            fail "trusted Linux account database contains a malformed record"
          if [ "$plar_uid" = "$render_uid" ]; then
            dri_found=$((dri_found + 1))
            [ "$dri_found" -eq 1 ] ||
              fail "trusted Linux account database contains duplicate uid records"
            render_user="$plar_user"
            dri_uid="$plar_uid"
            render_home="$plar_home"
          fi
        done </etc/passwd
        [ "$dri_found" = "1" ] ||
          fail "could not resolve the OS account record"
      fi
      ;;
    Darwin)
      dri_record="$("$dri_id" -P)" ||
        fail "could not resolve the OS account record"
      case "$dri_record" in
        *"$nl"*) fail "OS account lookup returned multiple records" ;;
      esac
      IFS=: read -r render_user dri_password dri_uid dri_gid dri_class dri_change dri_expire dri_gecos render_home dri_shell <<EOF
$dri_record
EOF
      ;;
    *) fail "unsupported platform $platform" ;;
  esac

  [ "$dri_uid" = "$render_uid" ] ||
    fail "OS account record does not match the process uid"
}

prepare_render_context() {
  derive_render_identity
  validate_home "$render_home"
  validate_user "$render_user"
  plist_target="$render_home/Library/LaunchAgents/${label}.plist"
  systemd_target="$render_home/.config/systemd/user/${unit_name}"
  log_dir="$render_home/Library/Logs/oauth-mux"
}

resolve_bin() {
  if [ -n "${OMUX_BIN:-}" ]; then
    validate_executable_path "$OMUX_BIN"
    [ -f "$OMUX_BIN" ] && [ -x "$OMUX_BIN" ] ||
      fail "OMUX_BIN must name a regular executable file"
    printf '%s\n' "$OMUX_BIN"
    return 0
  fi
  if command -v oauth-mux >/dev/null 2>&1; then
    rb_candidate="$(command -v oauth-mux)"
    validate_executable_path "$rb_candidate"
    printf '%s\n' "$rb_candidate"
    return 0
  fi
  for rb_candidate in "$render_home/.local/bin/oauth-mux" /usr/local/bin/oauth-mux \
    /opt/homebrew/bin/oauth-mux /usr/bin/oauth-mux; do
    if [ -x "$rb_candidate" ]; then
      validate_executable_path "$rb_candidate"
      printf '%s\n' "$rb_candidate"
      return 0
    fi
  done
  if [ -n "${1:-}" ]; then
    validate_executable_path "$1"
    printf '%s\n' "$1"
    return 0
  fi
  fail "oauth-mux binary not found (set OMUX_BIN=/abs/path or run: just install-local-dogfood)"
}

render_template() { # $1=template path, $2=binary path
  [ -f "$1" ] || fail "missing template $1"
  validate_home "$render_home"
  validate_user "$render_user"
  validate_executable_path "$2"
  validate_render_value "log directory" "$log_dir"
  rt_rendered="$(
    sed \
      -e "s|@OMUX_HOME@|$render_home|g" \
      -e "s|@OMUX_USER@|$render_user|g" \
      -e "s|@OMUX_BIN@|$2|g" \
      -e "s|@OMUX_LOG_DIR@|$log_dir|g" \
      "$1"
  )"
  if printf '%s\n' "$rt_rendered" | grep -q '@OMUX_'; then
    fail "$1: unresolved template marker survived rendering"
  fi
  printf '%s\n' "$rt_rendered"
}

canonical_plist() { # $1=binary path
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  oauth-mux keepalive LaunchAgent template (TIN-1830, TIN-3024).
  Rendered by scripts/keepalive-service.sh install; $render_home and $render_user
  come from the OS account record, while $1 and $log_dir are
  validated and substituted at install time.
  Guardrail: /usr/bin/env -i clears launchd's inherited environment before the
  fixed non-credential allowlist is applied. The binary reads credential stores
  live at runtime.
  The loop is bounded by design (100000 ticks, sleep capped at 60s);
  launchd owns residency via KeepAlive and restarts it on any exit.
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.xoxd.omux.keepalive</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/bin/env</string>
    <string>-i</string>
    <string>HOME=$render_home</string>
    <string>USER=$render_user</string>
    <string>PATH=/usr/bin:/bin:/usr/sbin:/sbin</string>
    <string>NO_COLOR=1</string>
    <string>$1</string>
    <string>keepalive</string>
    <string>--iterations</string>
    <string>100000</string>
    <string>--interval-ms</string>
    <string>60000</string>
    <string>--json</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>300</integer>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>$log_dir/keepalive.out.log</string>
  <key>StandardErrorPath</key>
  <string>$log_dir/keepalive.err.log</string>
</dict>
</plist>
EOF
}

check_darwin_plist_effective() { # $1=rendered text, $2=binary path
  [ -x /usr/bin/plutil ] ||
    fail "plist: /usr/bin/plutil is required for Darwin semantic validation"
  cdp_expected="$(canonical_plist "$2")"
  if ! cdp_actual_effective="$(
    printf '%s\n' "$1" |
      /usr/bin/plutil -convert xml1 -o - -- - 2>/dev/null
  )"; then
    fail "plist: /usr/bin/plutil rejected the rendered LaunchAgent"
  fi
  if ! cdp_expected_effective="$(
    printf '%s\n' "$cdp_expected" |
      /usr/bin/plutil -convert xml1 -o - -- - 2>/dev/null
  )"; then
    fail "plist: canonical LaunchAgent failed /usr/bin/plutil validation"
  fi
  [ "$cdp_actual_effective" = "$cdp_expected_effective" ] ||
    fail "plist: effective top-level dictionary differs from the canonical LaunchAgent"
}

check_unit_text() { # $1=rendered text, $2=name, $3=binary path for plist
  printf '%s' "$1" | grep -q 'keepalive' || fail "$2: keepalive verb missing"
  if printf '%s' "$1" | grep -q 'stay-afloat'; then
    fail "$2: stale stay-afloat phrasing present"
  fi
  if printf '%s' "$1" | grep -Eiq 'password|secret|bearer|authorization|api[_-]?key|refresh_token|access_token|client_secret|sops'; then
    fail "$2: credential-shaped content detected - units must stay credential-free"
  fi
  if printf '%s' "$1" | grep -q '@OMUX_'; then
    fail "$2: unresolved template marker survived rendering"
  fi

  if [ "$2" = "plist" ]; then
    cut_bin="${3:-}"
    validate_executable_path "$cut_bin"
    cut_expected="$(canonical_plist "$cut_bin")"
    [ "$1" = "$cut_expected" ] ||
      fail "plist: source must match the complete canonical LaunchAgent dictionary"
  fi
}

do_render() {
  # An explicitly-set OMUX_BIN must fail closed; the placeholder is only for
  # the no-binary-anywhere preview case.
  if [ -n "${OMUX_BIN:-}" ]; then
    dr_bin="$(resolve_bin)"
  else
    dr_bin="$(resolve_bin /usr/local/bin/oauth-mux)"
  fi
  validate_executable_path "$dr_bin"
  dr_plist="$(render_template "$plist_template" "$dr_bin")"
  dr_unit="$(render_template "$systemd_template" "$dr_bin")"
  check_unit_text "$dr_plist" "plist" "$dr_bin"
  if [ "$platform" = "Darwin" ]; then
    check_darwin_plist_effective "$dr_plist" "$dr_bin"
  fi
  check_unit_text "$dr_unit" "systemd unit"
  printf '# --- rendered %s ---\n' "$plist_template"
  printf '%s\n' "$dr_plist"
  printf '# --- rendered %s ---\n' "$systemd_template"
  printf '%s\n' "$dr_unit"
}

bootout_darwin_if_loaded() { # $1=OS-derived uid
  bd_uid="$1"
  if /bin/launchctl print "gui/$bd_uid/${label}" >/dev/null 2>&1; then
    if /bin/launchctl bootout "gui/$bd_uid" "$plist_target" >/dev/null 2>&1; then
      return 0
    fi
    return 3
  else
    bd_print_status=$?
    if [ "$bd_print_status" -eq "$launchctl_absent_status" ]; then
      return 0
    fi
    return 2
  fi
}

install_darwin() {
  in_bin="$(resolve_bin)"
  printf 'binary: %s\n' "$in_bin"
  "$in_bin" version >/dev/null 2>&1 || fail "$in_bin does not run; refusing to install a broken unit"
  in_rendered="$(render_template "$plist_template" "$in_bin")"
  check_unit_text "$in_rendered" "plist" "$in_bin"
  check_darwin_plist_effective "$in_rendered" "$in_bin"
  mkdir -p "$render_home/Library/LaunchAgents" "$log_dir"
  in_tmp="$(mktemp "$render_home/Library/LaunchAgents/.${label}.plist.tmp.XXXXXX")"
  printf '%s\n' "$in_rendered" >"$in_tmp"
  /usr/bin/plutil -lint "$in_tmp" >/dev/null ||
    { rm -f "$in_tmp"; fail "/usr/bin/plutil -lint rejected rendered plist"; }
  if bootout_darwin_if_loaded "$render_uid"; then
    :
  else
    in_bootout_status=$?
    rm -f "$in_tmp"
    case "$in_bootout_status" in
      2) fail "launchctl could not determine whether the existing job is loaded" ;;
      *) fail "launchctl could not boot out the loaded job" ;;
    esac
  fi
  mv -f "$in_tmp" "$plist_target"
  /bin/launchctl bootstrap "gui/$render_uid" "$plist_target"
  printf 'installed and loaded: %s\n' "$plist_target"
  printf 'logs: %s/keepalive.{out,err}.log\n' "$log_dir"
}

install_linux() {
  in_bin="$(resolve_bin)"
  printf 'binary: %s\n' "$in_bin"
  "$in_bin" version >/dev/null 2>&1 || fail "$in_bin does not run; refusing to install a broken unit"
  in_rendered="$(render_template "$systemd_template" "$in_bin")"
  check_unit_text "$in_rendered" "systemd unit"
  mkdir -p "$render_home/.config/systemd/user"
  in_tmp="$(mktemp "$render_home/.config/systemd/user/.${unit_name}.tmp.XXXXXX")"
  printf '%s\n' "$in_rendered" >"$in_tmp"
  mv -f "$in_tmp" "$systemd_target"
  systemctl --user daemon-reload
  systemctl --user enable --now "$unit_name"
  printf 'installed and enabled: %s\n' "$systemd_target"
  printf 'logs: journalctl --user -u %s\n' "$unit_name"
}

uninstall_darwin() {
  if bootout_darwin_if_loaded "$render_uid"; then
    :
  else
    un_bootout_status=$?
    case "$un_bootout_status" in
      2) fail "launchctl could not determine whether the job is loaded; plist preserved" ;;
      *) fail "launchctl could not boot out the loaded job; plist preserved" ;;
    esac
  fi
  rm -f "$plist_target"
  printf 'removed %s (log files left in place: %s)\n' "$plist_target" "$log_dir"
}

uninstall_linux() {
  systemctl --user disable --now "$unit_name" 2>/dev/null || true
  rm -f "$systemd_target"
  systemctl --user daemon-reload
  printf 'removed %s\n' "$systemd_target"
}

status_darwin() {
  sd_uid="$(os_uid)"
  printf 'service_label=%s\n' "$label"
  if /bin/launchctl print "gui/$sd_uid/${label}" >/dev/null 2>&1; then
    printf 'service_loaded=true\n'
  else
    sd_status=$?
    if [ "$sd_status" -eq "$launchctl_absent_status" ]; then
      printf 'service_loaded=false\n'
    else
      fail "launchctl could not determine service state"
    fi
  fi
}

status_linux() {
  systemctl --user status "$unit_name" --no-pager || true
  journalctl --user -u "$unit_name" -n 20 --no-pager 2>/dev/null || true
}

verify_offline() {
  vo_ok=1
  vo_tmpdir=""
  trap '[ -z "${vo_tmpdir:-}" ] || rm -rf "$vo_tmpdir"' EXIT
  if [ -n "${OMUX_BIN:-}" ]; then
    vo_bin="$(resolve_bin)"
  else
    vo_bin="$(resolve_bin /usr/local/bin/oauth-mux)"
  fi
  vo_plist="$(render_template "$plist_template" "$vo_bin")"
  vo_unit="$(render_template "$systemd_template" "$vo_bin")"
  check_unit_text "$vo_plist" "plist" "$vo_bin"
  check_unit_text "$vo_unit" "systemd unit"
  if printf '%s' "$vo_plist$vo_unit" | grep -q '@OMUX_'; then
    fail "unsubstituted template marker survived rendering"
  fi

  if [ "$platform" = "Darwin" ]; then
    check_darwin_plist_effective "$vo_plist" "$vo_bin"
    printf '/usr/bin/plutil effective dictionary validation: green\n'
  else
    printf 'Darwin /usr/bin/plutil effective validation: SKIPPED on %s\n' "$platform"
  fi

  # systemd static shape checks (honest floor when systemd is absent).
  for vo_pat in '\[Unit\]' '\[Service\]' '\[Install\]' '^ExecStart=' '^Restart=always' '^RestartSec=' '^WantedBy=default.target' '^Type=simple'; do
    printf '%s\n' "$vo_unit" | grep -Eq "$vo_pat" || { printf 'systemd unit missing %s\n' "$vo_pat" >&2; vo_ok=0; }
  done
  # every line must be blank, a comment, a [Section], or key=value
  vo_malformed="$(printf '%s\n' "$vo_unit" | grep -Ev '^$|^#|^\[[^][]*\]$|^[A-Za-z].*=' || true)"
  if [ -n "$vo_malformed" ]; then
    printf 'systemd unit malformed line(s):\n%s\n' "$vo_malformed" >&2
    vo_ok=0
  fi
  [ "$vo_ok" = "1" ] || fail "systemd unit static checks failed"

  if command -v systemd-analyze >/dev/null 2>&1; then
    [ -n "$vo_tmpdir" ] || vo_tmpdir="$(mktemp -d)"
    printf '%s\n' "$vo_unit" >"$vo_tmpdir/$unit_name"
    systemd-analyze verify --user "$vo_tmpdir/$unit_name" && printf 'systemd-analyze verify: green\n'
  else
    printf 'systemd-analyze unavailable on this host: full unit verify PENDING live Linux validation\n'
  fi
  printf 'verify: offline checks passed (this is lint-level proof only, not a live-service claim)\n'
}

cmd="${1:-}"
case "$cmd" in
  install)
    detect_platform
    prepare_render_context
    case "$platform" in
      Darwin) install_darwin ;;
      Linux) install_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  uninstall)
    detect_platform
    prepare_render_context
    case "$platform" in
      Darwin) uninstall_darwin ;;
      Linux) uninstall_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  status)
    detect_platform
    case "$platform" in
      Darwin) status_darwin ;;
      Linux) status_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  render)
    detect_platform
    prepare_render_context
    do_render
    ;;
  verify)
    detect_platform
    prepare_render_context
    verify_offline
    ;;
  -h|--help|help) usage; exit 0 ;;
  '') usage; exit 2 ;;
  *) usage; fail "unknown subcommand: $cmd" ;;
esac
