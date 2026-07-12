#!/bin/sh
set -eu

repo_root="$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)"
manifest="$repo_root/test/fixtures/v0.1.15-characterization/manifest.json"
baseline_commit="874a296dda66a6f8f9ac7b94d08996a94a32bd71"

jq -e '
  def expected_dispositions: [
    ["release_and_install", "preserve_until_v0.2_golden"],
    ["account_enrollment", "migrate_to_v0.2"],
    [("credential_" + "keepalive"), "migrate_to_v0.2"],
    ["status_and_doctor_json", "migrate_to_v0.2"],
    ["managed_codex", "preserve_until_adapter_parity"],
    ["socket_daemon_and_prepared_fallback", "remove_after_replacement"]
  ];
  .schema_version == 1
  and .baseline.tag == "v0.1.15"
  and .baseline.commit == "874a296dda66a6f8f9ac7b94d08996a94a32bd71"
  and .claim == "characterization_only"
  and (.surfaces | length == 6)
  and ([.surfaces[].id] | length == (unique | length))
  and all(.surfaces[];
    . as $surface
    | any(expected_dispositions[];
        .[0] == $surface.id and .[1] == $surface.disposition)
    and (.proofs | type == "array" and length > 0)
    and any(.proofs[];
      .ref == "v0.1.15"
      and (.kind == "test" or .kind == "contract" or .kind == "evidence"))
    and all(.proofs[];
      (.path | type == "string"
        and length > 0
        and test("^[A-Za-z0-9._/-]+$")
        and (startswith("/") | not)
        and (split("/") | index("..") == null))
      and ((.ref == "v0.1.15"
          and (.kind == "test" or .kind == "contract" or .kind == "evidence"))
        or (.ref == "current_authority" and .kind == "authority"))))
  and ([.surfaces[].id] | contains([
    "release_and_install",
    "account_enrollment",
    "credential_keepalive",
    "status_and_doctor_json",
    "managed_codex",
    "socket_daemon_and_prepared_fallback"
  ]))
' "$manifest" >/dev/null

if ! git -C "$repo_root" cat-file -e "$baseline_commit^{commit}" 2>/dev/null; then
  printf 'v0.1.15 baseline commit is unavailable; use a full-history checkout: %s\n' "$baseline_commit" >&2
  exit 1
fi

tag_commit="$(git -C "$repo_root" rev-parse 'v0.1.15^{commit}' 2>/dev/null || true)"
if [ "$tag_commit" != "$baseline_commit" ]; then
  printf 'v0.1.15 tag mismatch: expected %s, got %s\n' "$baseline_commit" "${tag_commit:-missing}" >&2
  exit 1
fi

proof_rows="$(jq -er '.surfaces[].proofs[] | [.path, .ref] | @tsv' "$manifest")"
printf '%s\n' "$proof_rows" | while IFS="$(printf '\t')" read -r rel ref; do
  if [ ! -e "$repo_root/$rel" ]; then
    printf 'characterization proof path does not exist: %s\n' "$rel" >&2
    exit 1
  fi

  if [ "$ref" = "v0.1.15" ] &&
    ! git -C "$repo_root" cat-file -e "$baseline_commit:$rel" 2>/dev/null; then
    printf 'characterization path was absent from the v0.1.15 commit: %s\n' "$rel" >&2
    exit 1
  fi
done

printf 'v0.1.15 characterization index is schema- and path-valid\n'
