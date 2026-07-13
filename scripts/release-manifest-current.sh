#!/usr/bin/env bash

# Private projection helpers for the shipped v0.1.15 release shape. This file
# is sourced by release scripts; it is not a public manifest query interface.

release_manifest_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_manifest_file="$release_manifest_repo_root/release-manifest.json"
release_manifest_current_fixture="$release_manifest_repo_root/test/fixtures/v0.1.15-characterization/release-layout.json"

release_manifest_require_current_v0_1_15() {
  local version="$1"

  if [ "$version" != "0.1.15" ]; then
    printf 'current release projection is pinned to v0.1.15, not v%s\n' "$version" >&2
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    printf 'release manifest projection requires jq\n' >&2
    return 127
  fi
  if [ ! -f "$release_manifest_file" ]; then
    printf 'release manifest is missing: %s\n' "$release_manifest_file" >&2
    return 1
  fi
  if [ ! -f "$release_manifest_current_fixture" ]; then
    printf 'v0.1.15 release layout fixture is missing: %s\n' \
      "$release_manifest_current_fixture" >&2
    return 1
  fi

  if ! jq -e --arg version "$version" --slurpfile expected_file "$release_manifest_current_fixture" '
    def safe_atom:
      type == "string"
      and length > 0
      and test("^[A-Za-z0-9._+:/-]+$")
      and (contains("//") | not)
      and (split("/") | index("..") == null);
    def unresolved:
      .sha256 == null
      and .signature_ref == null
      and .sbom_ref == null
      and .provenance_ref == null;
    def layout_projection:
      {
        schema_version: 1,
        release_version: .release.version,
        product: {
          package_name: .product.package_name,
          primary_executable: .product.primary_executable,
          compatibility_links: .product.compatibility_links,
          storage_namespace: .product.storage_namespace
        },
        targets: [
          .targets[] | {id, release_directory, cpu_arch, os, artifact}
        ],
        release_assets: [
          .release_assets[] | {
            id,
            kind,
            target_id,
            source_path,
            staged_path,
            release_name,
            materialization_state,
            current_v0_1_15_members
          }
        ]
      };
    def canonical_layout:
      .targets |= sort_by(.id)
      | .release_assets |= sort_by(.id);

    $expected_file[0] as $expected
    | .schema_version == 1
    and .phase == "declaration"
    and .release.version == $version
    and .release.build_id.value == null
    and .release.source_commit == null
    and ($expected.schema_version == 1 and $expected.release_version == "0.1.15")
    and (.targets | type == "array")
    and all(.targets[];
      (.id | safe_atom)
      and (.release_directory | safe_atom)
      and (.cpu_arch | safe_atom)
      and (.os | safe_atom))
    and (.release_assets | type == "array")
    and all(.release_assets[];
      (.id | safe_atom)
      and (.staged_path | safe_atom)
      and (.release_name | safe_atom)
      and (.current_v0_1_15_members | type == "array")
      and ([.current_v0_1_15_members[]] | length == (unique | length))
      and all(.current_v0_1_15_members[]; safe_atom)
      and unresolved)
    and ((layout_projection | canonical_layout) == ($expected | canonical_layout))
  ' "$release_manifest_file" >/dev/null; then
    printf 'release manifest does not satisfy the current v0.1.15 packaging contract: %s\n' \
      "$release_manifest_file" >&2
    return 1
  fi
}

release_manifest_archive_rows() {
  jq -r '
    .targets as $targets
    | .release_assets[]
    | select(.kind == "archive")
    | . as $asset
    | ($targets[] | select(.id == $asset.target_id)) as $target
    | [
        $target.id,
        $target.release_directory,
        $target.os,
        $asset.staged_path,
        $asset.release_name,
        ($asset.current_v0_1_15_members | join(","))
      ]
    | @tsv
  ' "$release_manifest_file"
}

release_manifest_package_rows() {
  jq -r '
    .targets as $targets
    | .release_assets[]
    | select(.kind == "deb" or .kind == "rpm")
    | . as $asset
    | ($targets[] | select(.id == $asset.target_id)) as $target
    | [
        $asset.kind,
        $target.id,
        $target.release_directory,
        $target.cpu_arch,
        $asset.staged_path,
        $asset.release_name,
        ($asset.current_v0_1_15_members | join(","))
      ]
    | @tsv
  ' "$release_manifest_file"
}

release_manifest_github_attachment_paths() {
  jq -r '
    .release_assets[]
    | select(
        .kind == "archive"
        or .kind == "deb"
        or .kind == "rpm"
        or .kind == "installer"
        or .kind == "checksums")
    | .staged_path
  ' "$release_manifest_file"
}

release_manifest_formula_staged_path() {
  jq -r '.release_assets[] | select(.kind == "formula") | .staged_path' \
    "$release_manifest_file"
}

release_manifest_installer_staged_path() {
  jq -er '.release_assets[] | select(.id == "curl-installer") | .staged_path' \
    "$release_manifest_file"
}

release_manifest_checksums_staged_path() {
  jq -er '.release_assets[] | select(.id == "checksums") | .staged_path' \
    "$release_manifest_file"
}

release_manifest_archive_staged_path() {
  local target_id="$1"
  jq -er --arg target_id "$target_id" '
    .release_assets[]
    | select(.kind == "archive" and .target_id == $target_id)
    | .staged_path
  ' "$release_manifest_file"
}
