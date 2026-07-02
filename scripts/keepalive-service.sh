#!/usr/bin/env sh
# Operator-explicit management of the oauth-mux keepalive user service
# (TIN-1830). POSIX sh; nothing here runs at build or package time.
set -eu

repo_root="$(cd "$(dirname "$0")/.." && pwd)"

label="dev.xoxd.omux.keepalive"
unit_name="oauth-mux-keepalive.service"
plist_template="$repo_root/dist/launchd/${label}.plist.tmpl"
systemd_template="$repo_root/dist/systemd/${unit_name}.tmpl"
plist_target="$HOME/Library/LaunchAgents/${label}.plist"
systemd_target="$HOME/.config/systemd/user/${unit_name}"
log_dir="$HOME/Library/Logs/oauth-mux"
platform="$(uname -s)"
nl='
'

usage() {
  cat <<'EOF'
usage: keepalive-service.sh <install|uninstall|status|render|verify>

Operator-explicit management of the oauth-mux keepalive user service
(launchd LaunchAgent on macOS, systemd user unit on Linux). Nothing here
runs automatically at build or package time.

  install    render unit with resolved binary path, lint, place, load/enable
  uninstall  unload/disable and remove the placed unit file
  status     show service state and recent log/journal lines
  render     print rendered unit(s) to stdout without installing
  verify     offline static checks (lint, correct verb, credential-free)

env: OMUX_BIN=/abs/path/to/oauth-mux overrides binary resolution.
EOF
}

fail() { printf 'keepalive-service: %s\n' "$1" >&2; exit 1; }

resolve_bin() {
  if [ -n "${OMUX_BIN:-}" ]; then
    [ -x "$OMUX_BIN" ] || fail "OMUX_BIN=$OMUX_BIN is not an executable file"
    printf '%s\n' "$OMUX_BIN"
    return 0
  fi
  if command -v oauth-mux >/dev/null 2>&1; then
    command -v oauth-mux
    return 0
  fi
  for rb_candidate in "$HOME/.local/bin/oauth-mux" /usr/local/bin/oauth-mux \
    /opt/homebrew/bin/oauth-mux /usr/bin/oauth-mux; do
    if [ -x "$rb_candidate" ]; then
      printf '%s\n' "$rb_candidate"
      return 0
    fi
  done
  fail "oauth-mux binary not found (set OMUX_BIN=/abs/path or run: just install-local-dogfood)"
}

render_template() { # $1=template path, $2=binary path
  [ -f "$1" ] || fail "missing template $1"
  case "$2$log_dir" in
    *'|'* | *'&'* | *"$nl"*) fail "refusing path containing '|', '&', or newline" ;;
  esac
  sed -e "s|@OMUX_BIN@|$2|g" -e "s|@OMUX_LOG_DIR@|$log_dir|g" "$1"
}

check_unit_text() { # $1=rendered text, $2=name  (shared offline assertions)
  printf '%s' "$1" | grep -q 'keepalive' || fail "$2: keepalive verb missing"
  if printf '%s' "$1" | grep -q 'stay-afloat'; then
    fail "$2: stale stay-afloat phrasing present"
  fi
  if printf '%s' "$1" | grep -Eiq 'password|secret|bearer|authorization|api[_-]?key|refresh_token|access_token|client_secret|sops'; then
    fail "$2: credential-shaped content detected - units must stay credential-free"
  fi
}

do_render() {
  dr_bin="$(resolve_bin 2>/dev/null || printf '/usr/local/bin/oauth-mux')"
  printf '# --- rendered %s ---\n' "$plist_template"
  render_template "$plist_template" "$dr_bin"
  printf '# --- rendered %s ---\n' "$systemd_template"
  render_template "$systemd_template" "$dr_bin"
}

install_darwin() {
  in_bin="$(resolve_bin)"
  printf 'binary: %s\n' "$in_bin"
  "$in_bin" version >/dev/null 2>&1 || fail "$in_bin does not run; refusing to install a broken unit"
  in_rendered="$(render_template "$plist_template" "$in_bin")"
  check_unit_text "$in_rendered" "plist"
  mkdir -p "$HOME/Library/LaunchAgents" "$log_dir"
  in_tmp="$(mktemp "$HOME/Library/LaunchAgents/.${label}.plist.tmp.XXXXXX")"
  printf '%s\n' "$in_rendered" >"$in_tmp"
  plutil -lint "$in_tmp" >/dev/null || { rm -f "$in_tmp"; fail "plutil -lint rejected rendered plist"; }
  launchctl bootout "gui/$(id -u)" "$plist_target" 2>/dev/null || true
  mv -f "$in_tmp" "$plist_target"
  launchctl bootstrap "gui/$(id -u)" "$plist_target"
  printf 'installed and loaded: %s\n' "$plist_target"
  printf 'logs: %s/keepalive.{out,err}.log\n' "$log_dir"
}

install_linux() {
  in_bin="$(resolve_bin)"
  printf 'binary: %s\n' "$in_bin"
  "$in_bin" version >/dev/null 2>&1 || fail "$in_bin does not run; refusing to install a broken unit"
  in_rendered="$(render_template "$systemd_template" "$in_bin")"
  check_unit_text "$in_rendered" "systemd unit"
  mkdir -p "$HOME/.config/systemd/user"
  in_tmp="$(mktemp "$HOME/.config/systemd/user/.${unit_name}.tmp.XXXXXX")"
  printf '%s\n' "$in_rendered" >"$in_tmp"
  mv -f "$in_tmp" "$systemd_target"
  systemctl --user daemon-reload
  systemctl --user enable --now "$unit_name"
  printf 'installed and enabled: %s\n' "$systemd_target"
  printf 'logs: journalctl --user -u %s\n' "$unit_name"
}

uninstall_darwin() {
  launchctl bootout "gui/$(id -u)" "$plist_target" 2>/dev/null || true
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
  if st_out="$(launchctl print "gui/$(id -u)/${label}" 2>/dev/null)"; then
    printf '%s\n' "$st_out" | sed -n '1,20p'
  else
    printf 'service not loaded (%s absent from gui/%s)\n' "$label" "$(id -u)"
  fi
  for st_f in "$log_dir/keepalive.out.log" "$log_dir/keepalive.err.log"; do
    if [ -f "$st_f" ]; then
      printf -- '--- tail %s ---\n' "$st_f"
      tail -n 10 "$st_f"
    fi
  done
}

status_linux() {
  systemctl --user status "$unit_name" --no-pager || true
  journalctl --user -u "$unit_name" -n 20 --no-pager 2>/dev/null || true
}

verify_offline() {
  vo_ok=1
  vo_tmpdir=""
  vo_bin="$(resolve_bin 2>/dev/null || printf '/usr/local/bin/oauth-mux')"
  vo_plist="$(render_template "$plist_template" "$vo_bin")"
  vo_unit="$(render_template "$systemd_template" "$vo_bin")"
  check_unit_text "$vo_plist" "plist"
  check_unit_text "$vo_unit" "systemd unit"
  if printf '%s' "$vo_plist$vo_unit" | grep -q '@OMUX_'; then
    fail "unsubstituted template marker survived rendering"
  fi

  if command -v plutil >/dev/null 2>&1; then
    vo_tmpdir="$(mktemp -d)"
    printf '%s\n' "$vo_plist" >"$vo_tmpdir/${label}.plist"
    plutil -lint "$vo_tmpdir/${label}.plist"
  else
    printf 'plutil unavailable on this host: plist lint SKIPPED\n'
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
    case "$platform" in
      Darwin) install_darwin ;;
      Linux) install_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  uninstall)
    case "$platform" in
      Darwin) uninstall_darwin ;;
      Linux) uninstall_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  status)
    case "$platform" in
      Darwin) status_darwin ;;
      Linux) status_linux ;;
      *) fail "unsupported platform $platform" ;;
    esac
    ;;
  render) do_render ;;
  verify) verify_offline ;;
  -h|--help|help) usage; exit 0 ;;
  '') usage; exit 2 ;;
  *) usage; fail "unknown subcommand: $cmd" ;;
esac
