#!/bin/sh
set -eu

url=""
for arg in "$@"; do
  case "$arg" in
    http://*|https://*) url="$arg" ;;
  esac
done

if [ -z "$url" ]; then
  exec /usr/bin/open "$@"
fi

profile="${OMUX_CLAUDE_BROWSER_PROFILE:-}"
if [ -z "$profile" ]; then
  profile="${TMPDIR:-/tmp}/omux-claude-browser-$$"
fi

chrome=""
for candidate in \
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "$HOME/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  "/Applications/Chromium.app/Contents/MacOS/Chromium" \
  "$HOME/Applications/Chromium.app/Contents/MacOS/Chromium"
do
  if [ -x "$candidate" ]; then
    chrome="$candidate"
    break
  fi
done

if [ -z "$chrome" ]; then
  echo "omux: no Chrome/Chromium executable found for isolated Claude login" >&2
  echo "omux: auth URL was not opened to avoid falling back to a shared browser session" >&2
  exit 1
fi

mkdir -p "$profile"
"$chrome" \
  --user-data-dir="$profile" \
  --incognito \
  --new-window \
  --no-first-run \
  --no-default-browser-check \
  "$url" >/dev/null 2>&1 &

exit 0
