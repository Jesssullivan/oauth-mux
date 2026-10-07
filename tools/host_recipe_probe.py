"""Bounded read-only public recipe discovery on the named Neo teletype."""
import argparse
import hashlib
import json
import os
import re
import subprocess
from ssh_policy import operator_config
from host_closure_transfer import bounded

COMMAND = r'''set -eu
immutable_file() {
  omux_file="$1"; omux_hops=0
  while test -L "$omux_file"; do
    omux_hops=$((omux_hops + 1)); test "$omux_hops" -le 8 || return 1
    omux_file=$(readlink "$omux_file")
    case "$omux_file" in /nix/store/*) ;; *) return 1 ;; esac
    case "$omux_file" in */../*|*/./*|*//*) return 1 ;; esac
  done
  test -f "$omux_file" || return 1
  omux_meta=$(stat -f '%u:%Lp' "$omux_file")
  omux_owner=${omux_meta%%:*}; omux_mode=${omux_meta#*:}
  case "$omux_mode" in *[!0-7]*|"") return 1 ;; esac
  { test "$omux_owner" -eq 0 || test "$omux_owner" -eq "$(id -u)"; } || return 1
  test "$((0$omux_mode & 022))" -eq 0 || return 1
  omux_admitted=$(stat -f '%d:%i:%u:%Lp:%z:%m:%c' "$omux_file")
}
omux_count=0
for omux_closure in /nix/store/*-omux-bazel-closure; do
  test -d "$omux_closure" && test ! -L "$omux_closure" || continue
  omux_count=$((omux_count + 1)); test "$omux_count" -le 32 || exit 3
  omux_name=${omux_closure##*/}
  if immutable_file "$omux_closure/native.json"; then
    bytes=$(wc -c < "$omux_file"); bytes=$((bytes)); test "$bytes" -le 65536 || continue
    printf 'FILE %s/native.json %s\n' "$omux_name" "$bytes"
    head -c 65536 "$omux_file"; printf '\nEND\n'
    test "$omux_admitted" = "$(stat -f '%d:%i:%u:%Lp:%z:%m:%c' "$omux_file")" || exit 3
  fi
  for omux_member in store-paths registration; do
    if immutable_file "$omux_closure/$omux_member"; then
      bytes=$(wc -c < "$omux_file"); bytes=$((bytes)); test "$bytes" -le 4194304 || continue
      omux_hash=$(shasum -a 256 "$omux_file"); omux_hash=${omux_hash%% *}
      omux_lines=$(wc -l < "$omux_file"); omux_lines=$((omux_lines))
      test "$omux_admitted" = "$(stat -f '%d:%i:%u:%Lp:%z:%m:%c' "$omux_file")" || exit 3
      printf 'META %s %s %s %s\n' "$omux_name" "$omux_member" "$omux_hash" "$omux_lines"
    fi
  done
done
count=0
files=0
test -d "$HOME" && test ! -L "$HOME" || exit 3
for root in "$HOME/git" "$HOME/Documents" "$HOME/Projects"; do
  test -d "$root" && test ! -L "$root" || continue
  for project in "$root"/legalab-lanes/gf-darwin-platform-* "$root"/ASFW* "$root"/asfw* "$root"/ASFireWire* "$root"/asfirewire* "$root"/cmux* "$root"/legalab*; do
    test -d "$project" && test ! -L "$project" || continue
    test ! -L "${project%/*}" || continue
    count=$((count + 1)); test "$count" -le 64 || exit 3
    name=${project##*/}
    case "$name" in *[!A-Za-z0-9._-]*) continue ;; esac
    printf 'PROJECT %s\n' "$name"
    for file in AGENTS.md CLAUDE.md Justfile justfile justfile.flywheel .bazelrc .bazelrc.flywheel .bazelversion MODULE.bazel BUILD.bazel; do
      path="$project/$file"
      test -f "$path" && test ! -L "$path" || continue
      bytes=$(wc -c < "$path"); test "$bytes" -le 65536 || continue
      bytes=$((bytes))
      files=$((files + 1)); test "$files" -le 32 || continue
      printf 'FILE %s/%s %s\n' "$name" "$file" "$bytes"
      head -c 65536 "$path"
      printf '\nEND\n'
    done
  done
done
omux_tool=$(command -v gloriousflywheel-bazel 2>/dev/null || true)
if test -z "$omux_tool"; then
  for omux_candidate in /run/current-system/sw/bin/gloriousflywheel-bazel "$HOME/.nix-profile/bin/gloriousflywheel-bazel" /nix/var/nix/profiles/default/bin/gloriousflywheel-bazel; do
    if test -f "$omux_candidate"; then omux_tool="$omux_candidate"; break; fi
  done
fi
if test -z "$omux_tool"; then printf 'TOOL missing\n'; fi
if test -n "$omux_tool"; then
  omux_parent=$(cd -P "${omux_tool%/*}" && pwd -P)
  omux_tool="$omux_parent/${omux_tool##*/}"
  case "$omux_tool" in
    /nix/store/*/bin/gloriousflywheel-bazel)
      printf 'TOOL store\n'
      omux_hops=0
      while test -L "$omux_tool"; do
        omux_hops=$((omux_hops + 1)); test "$omux_hops" -le 8 || exit 3
        omux_target=$(readlink "$omux_tool")
        case "$omux_target" in /nix/store/*/bin/gloriousflywheel-bazel) omux_tool="$omux_target" ;; *) printf 'TOOL rejected-alias\n'; break ;; esac
      done
      if test -f "$omux_tool" && test ! -L "$omux_tool"; then
        omux_meta=$(stat -f '%u:%Lp' "$omux_tool")
        omux_owner=${omux_meta%%:*}; omux_mode=${omux_meta#*:}
        case "$omux_mode" in *[!0-7]*|"") exit 3 ;; esac
        if { test "$omux_owner" -eq 0 || test "$omux_owner" -eq "$(id -u)"; } && test "$((0$omux_mode & 022))" -eq 0; then
          bytes=$(wc -c < "$omux_tool"); bytes=$((bytes))
          if test "$bytes" -le 65536; then
            printf 'FILE installed-gloriousflywheel-bazel/wrapper %s\n' "$bytes"
            head -c 65536 "$omux_tool"
            printf '\nEND\n'
          fi
        fi
      fi
      ;;
    *) printf 'TOOL outside-store\n' ;;
  esac
fi
'''

LAB_COMMAND = r'''set -eu
test -d "$HOME" && test ! -L "$HOME" || exit 3
test -d "$HOME/git" && test ! -L "$HOME/git" || exit 3
omux_count=0
omux_total=0
omux_candidates=0
for omux_project in lab blahaj GloriousFlywheel gloriousflywheel; do
  omux_root="$HOME/git/$omux_project"
  test -d "$omux_root" && test ! -L "$omux_root" || continue
  printf 'PROJECT %s\n' "$omux_project"
  if test -d "$omux_root/scripts" && test ! -L "$omux_root/scripts"; then
    for omux_script in "$omux_root"/scripts/*bazel* "$omux_root"/scripts/*profile* "$omux_root"/scripts/*platform* "$omux_root"/scripts/*darwin*; do
      test -f "$omux_script" && test ! -L "$omux_script" || continue
      omux_name=${omux_script##*/}
      case "$omux_name" in *[!A-Za-z0-9._-]*) continue ;; esac
      omux_candidates=$((omux_candidates + 1)); test "$omux_candidates" -le 128 || exit 3
      printf 'CANDIDATE %s/scripts/%s\n' "$omux_project" "$omux_name"
    done
  fi
  for omux_relative in AGENTS.md README.md flake.nix .bazelrc .bazelrc.flywheel justfile.flywheel scripts/gloriousflywheel-bazel.sh scripts/bazel-cache-backed.sh scripts/bazel-rbe-proof.sh scripts/gf-action-client.sh scripts/gf-platform.sh scripts/gf-profile.sh docs/current-state.md docs/product/golden-objective.md docs/reference/gloriousflywheel-cache-rbe-contract.md nix/darwin/petting-zoo-mini.nix nix/darwin/modules/gf-reapi-darwin-worker.nix nix/hosts/petting-zoo-mini.nix services/gf-reapi-cell/internal/cell/platform.go services/gf-reapi-cell/internal/cell/worker.go; do
    omux_path="$omux_root/$omux_relative"
    omux_parent="$omux_root"
    omux_remaining="$omux_relative"
    omux_safe=true
    while case "$omux_remaining" in */*) true ;; *) false ;; esac; do
      omux_component=${omux_remaining%%/*}; omux_remaining=${omux_remaining#*/}
      omux_parent="$omux_parent/$omux_component"
      test ! -L "$omux_parent" || exit 3
      if test ! -d "$omux_parent"; then omux_safe=false; break; fi
    done
    test "$omux_safe" = true || continue
    test -f "$omux_path" && test ! -L "$omux_path" || continue
    omux_bytes=$(wc -c < "$omux_path"); omux_bytes=$((omux_bytes))
    test "$omux_bytes" -le 262144 || continue
    omux_total=$((omux_total + omux_bytes)); test "$omux_total" -le 4194304 || exit 3
    omux_count=$((omux_count + 1)); test "$omux_count" -le 64 || exit 3
    printf 'FILE %s/%s %s\n' "$omux_project" "$omux_relative" "$omux_bytes"
    head -c 262144 "$omux_path"; printf '\nEND\n'
  done
done
'''

def summarize(output):
    if len(output) > 5 * 1024 * 1024:
        raise ValueError('bounded recipe output rejected')
    files = []
    for match in re.finditer(rb'^FILE ([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+) ([0-9]{1,6})\n(.*?)\nEND\n', output, re.M | re.S):
        source = match.group(3)
        if any(part in {b'.', b'..'} for part in match.group(1).split(b'/')):
            raise ValueError('public file path rejected')
        if len(source) != int(match.group(2)):
            raise ValueError('public file framing rejected')
        text = source.decode('utf-8', errors='replace')
        if match.group(1).endswith(b'/native.json'):
            native = json.loads(text)
            expected = {'system','packages','libc_abi','runtime_store_paths','qt_runtime_store_paths','dynamic_linker','tools','apple','cc','cxx','ar','linker','nm','strip','objcopy','objdump','builtin_include_directories'}
            if not isinstance(native, dict) or set(native) != expected or native['system'] not in {'aarch64-darwin','x86_64-darwin','aarch64-linux','x86_64-linux'}:
                raise ValueError('public manifest schema rejected')
            def paths(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key not in {'sdk_version','swift_version','system','libc_abi'}:
                            paths(child)
                elif isinstance(value, list):
                    for child in value: paths(child)
                elif value is not None and (not isinstance(value, str) or not re.fullmatch(r'/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._-]+(?:/[A-Za-z0-9+._/-]+)?', value) or '..' in value.split('/')):
                    raise ValueError('immutable manifest path rejected')
            paths(native)
            apple = native['apple']
            if native['system'].endswith('darwin') and (not isinstance(apple, dict) or apple.get('sdk_version') != '14.4'):
                raise ValueError('declared SDK version rejected')
            name = match.group(1).decode('ascii').split('/')[0]
            if not re.fullmatch(r'[0-9a-z]{32}-omux-bazel-closure', name):
                raise ValueError('public closure name rejected')
            files.append({'closure_basename':name,'manifest_sha256':hashlib.sha256(source).hexdigest(),'system':native['system'],'sdk_version':apple.get('sdk_version') if apple else None,'package_count':len(native['packages'])})
            continue
        flags = sorted(set(re.findall(r'--(?:remote_executor|remote_cache|remote_instance_name|remote_local_fallback|remote_accept_cached|spawn_strategy|extra_execution_platforms|platforms|jobs)(?=[=\s])', text)))
        references = sorted(set(re.findall(r'(?<![A-Za-z0-9_./-])(?:tools|scripts|nix|cli|services|docs)/[A-Za-z0-9_./-]+\.(?:sh|py|bzl|nix|go|md)', text)))[:64]
        references = [item for item in references if '..' not in item.split('/')]
        semantics = sorted(set(re.findall(r'--(?:remote_local_fallback=(?:false|true)|remote_accept_cached=(?:false|true)|spawn_strategy=(?:remote|local|sandboxed)|jobs=[1-9][0-9]?)(?![A-Za-z0-9_])', text)))
        variables = sorted(set(re.findall(r'\b(?:GF|RBE|BAZEL|OMUX)_[A-Z][A-Z0-9_]{0,63}\b', text)))[:64]
        tools = sorted(set(re.findall(r'\b(?:gloriousflywheel-bazel|gf-action-client|bazelisk|bazel-cache-backed|bazel-rbe-proof)\b', text)))
        version = text.strip() if match.group(1).endswith(b'/.bazelversion') and re.fullmatch(r'[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}', text.strip()) else None
        routing = sorted(set(re.findall(r'\b(?:gf\.platform|nix_closure|OSFamily|ISA|toolchainPolicy|closureDigest|startServices)\b', text)))
        daemon_markers = {
            'determinate_mentioned': bool(re.search(r'\bDeterminate\b|\bdeterminateNix\b', text, re.I)),
            'nix_darwin_management_disabled': bool(re.search(r'\bnix\.enable\s*=\s*false\s*;', text)),
            'custom_config_path_mentioned': '/etc/nix/nix.custom.conf' in text,
            'default_profile_daemon_mentioned': '/nix/var/nix/profiles/default/bin/nix-daemon' in text,
            'daemon_socket_path_mentioned': '/nix/var/nix/daemon-socket/socket' in text,
            'stdio_option_mentioned': bool(re.search(r'(?<![A-Za-z0-9_-])--stdio(?![A-Za-z0-9_-])', text)),
            'ssh_ng_mentioned': 'ssh-ng' in text,
            'remote_program_option_mentioned': 'remote-program' in text,
        }
        files.append({'project_file': match.group(1).decode('ascii'), 'bytes': len(source), 'sha256': hashlib.sha256(source).hexdigest(), 'remote_flag_names': flags, 'remote_semantics':semantics, 'configuration_variable_names':variables, 'dispatch_tool_names':tools, 'bazel_version':version, 'public_script_references': references, 'routing_field_names': routing, 'nix_daemon_entrypoint_markers': daemon_markers, 'bazel9_mentioned': bool(re.search(r'(?:bazel|bazelisk)[^\n]{0,30}\b9(?:\.[0-9]+)', text, re.I)), 'darwin_mentioned': bool(re.search(r'darwin|macos', text, re.I)), 'pzm_mentioned': bool(re.search(r'\bpzm\b|petting.zoo', text, re.I))})
    return files

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', required=True)
    parser.add_argument('--scope', choices=('native', 'lab-gf'), default='native')
    args = parser.parse_args()
    try:
        with operator_config() as options:
            env = {name: value for name, value in os.environ.items() if name in {'HOME', 'PATH', 'SSH_AUTH_SOCK'}}
            status, output, _ = bounded([args.ssh, *options, '-oBatchMode=yes', '-oConnectTimeout=10', '-oConnectionAttempts=1', '-oStrictHostKeyChecking=yes', '-oForwardAgent=no', '-oClearAllForwardings=yes', 'neo', LAB_COMMAND if args.scope == 'lab-gf' else COMMAND], env, seconds=45, bound=5 * 1024 * 1024)
        files = summarize(output) if status == 0 else []
        projects = sorted(set(item.decode('ascii') for item in re.findall(rb'^PROJECT ([A-Za-z0-9._-]+)$', output, re.M)))[:64]
        tool_states = sorted(set(item.decode('ascii') for item in re.findall(rb'^TOOL (missing|store|outside-store|rejected-alias)$', output, re.M)))
        metadata = [{'closure_basename':name.decode('ascii'),'member':member.decode('ascii'),'sha256':digest.decode('ascii'),'line_count':int(count)} for name,member,digest,count in re.findall(rb'^META ([0-9a-z]{32}-omux-bazel-closure) (store-paths|registration) ([a-f0-9]{64}) ([0-9]{1,7})$', output,re.M)]
        candidates = sorted(set(value.decode('ascii') for value in re.findall(rb'^CANDIDATE ([A-Za-z0-9._-]+/scripts/[A-Za-z0-9._-]+)$', output, re.M)))[:128]
        print(json.dumps({'host_alias':'neo', 'scope':args.scope, 'access':'read-only fixed public recipe and closure metadata', 'exit_code':status, 'projects':projects, 'installed_tool_states':tool_states, 'files':files, 'public_script_candidates':candidates, 'closure_metadata':metadata, 'passed':status == 0}, sort_keys=True))
        return 0 if status == 0 else 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired, KeyboardInterrupt):
        print(json.dumps({'host_alias':'neo','passed':False,'gate':'bounded public recipe inspection unavailable'}))
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
