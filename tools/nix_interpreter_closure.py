"""Select exact interpreter closures from already declared Nix registrations.

No Nix query, evaluator, downloader or builder is invoked. Self references and
reference cycles terminate through visited-set traversal, without dropping any
reachable root. Optional finite native capabilities use their exact resolved
executable root plus Bash; compiler inventories remain unchanged.
"""
import argparse
import json
from pathlib import Path
import re

STORE = r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+"
MAX_RECORDS = 4096
QUERY_GROUP = "codex_metadata_query"
QUERY_PACKAGES = ("bazel", "bash", "coreutils", "python", "git", "bazel_jdk")
CAPABILITIES = frozenset(("dbus_run_session", "dbus_daemon", "gnome_keyring_daemon",
                          "patchelf", "openssl_tool", "systemctl", "moc", "rcc", "uic", "secret_tool"))


def current_flake_path_refusal(value, *, drv=False):
    """Pinned Nix 2.34.6 canonical logical StorePath; no host path resolution."""
    if not isinstance(value, str):
        return "type"
    if not value.startswith("/nix/store/"):
        return "layout"
    basename = value[len("/nix/store/"):]
    if len(basename) < 34 or basename[32] != "-" or "/" in basename:
        return "layout"
    if re.fullmatch("[0123456789abcdfghijklmnpqrsvwxyz]{32}", basename[:32]) is None:
        return "hash"
    name = basename[33:]
    if not 1 <= len(name) <= 211:
        return "name-bound"
    if name in {".", ".."} or name.startswith((".-", "..-")):
        return "name-prefix"
    if re.fullmatch("[A-Za-z0-9+._?=-]+", name) is None:
        return "name-characters"
    if drv and not name.endswith(".drv"):
        return "derivation-suffix"
    return None


def registrations(text, declared, *, current_flake_paths=False):
    # This code-selected mode is exclusive to generated current-flake readback.
    # Declared runtime seeds and all existing callers retain their exact grammar.
    if type(current_flake_paths) is not bool:
        raise ValueError("registration path policy")
    def valid_path(value, *, drv=False):
        if current_flake_paths:
            return current_flake_path_refusal(value, drv=drv) is None
        return re.fullmatch(STORE + (r"\.drv" if drv else ""), value) is not None
    if len(text) > 4 * 1024 * 1024:
        raise ValueError("registration bound")
    if not declared or len(declared) > MAX_RECORDS or len(set(declared)) != len(declared):
        raise ValueError("declared root set")
    if any(not valid_path(root) for root in declared):
        raise ValueError("declared root syntax")
    lines = text.splitlines()
    records, cursor = {}, 0
    while cursor < len(lines):
        if len(records) >= MAX_RECORDS or cursor + 5 > len(lines):
            raise ValueError("registration shape")
        root, nar_hash, size, deriver, count = lines[cursor:cursor + 5]
        if (not valid_path(root) or root in records
                or not re.fullmatch(r"sha256:(?:[0-9abcdfghijklmnpqrsvwxyz]{52}|[0-9a-f]{64})", nar_hash)
                or not re.fullmatch(r"[1-9][0-9]{0,18}", size)
                or not re.fullmatch(r"[0-9]{1,4}", count)
                or (deriver and not valid_path(deriver, drv=True))):
            raise ValueError("registration record")
        if int(size) > (1 << 63) - 1 or int(count) > MAX_RECORDS:
            raise ValueError("registration numeric bound")
        encoded = nar_hash.split(":", 1)[1]
        if len(encoded) == 52:
            alphabet = "0123456789abcdfghijklmnpqrsvwxyz"
            number = 0
            for character in encoded:
                number = number * 32 + alphabet.index(character)
            if number >= (1 << 256):
                raise ValueError("registration NAR hash range")
        end = cursor + 5 + int(count)
        references = lines[cursor + 5:end]
        if (len(references) != int(count) or len(set(references)) != len(references)
                or any(not valid_path(ref) for ref in references)):
            raise ValueError("registration references")
        records[root] = {"references": references, "record": lines[cursor:end]}
        cursor = end
    if set(records) != set(declared) or any(ref not in records for item in records.values() for ref in item["references"]):
        raise ValueError("registration exact graph")
    return records


def reachable(records, seeds):
    if not seeds or any(seed not in records for seed in seeds):
        raise ValueError("interpreter root missing")
    visited, pending = set(), list(seeds)
    while pending:
        root = pending.pop()
        if root in visited:
            continue
        visited.add(root)
        pending.extend(ref for ref in records[root]["references"] if ref not in visited)
    return sorted(visited)


def select(native, declared, registration, inventory, resolved_tools=None):
    records = registrations(registration, declared)
    packages = native["packages"]
    bash = packages["bash"]["out"]
    files = inventory["files"]
    if not isinstance(files, list) or len(files) > 1000000 or len(files) != len(set(files)):
        raise ValueError("file inventory shape")
    indexed = {}
    for file in files:
        if (not isinstance(file, str) or len(file) > 4096 or file.startswith("/")
                or any(part in {"", ".", ".."} for part in file.split("/"))
                or any(character in file for character in "\\:\n\r\x00")):
            raise ValueError("file inventory path")
        parts = file.split("/", 2)
        # A store object may itself be a regular file (e.g. writeText), not
        # solely a directory containing descendants. Index both forms by the
        # exact basename component; prefix collisions cannot extend authority.
        if len(parts) >= 2 and parts[0] == "closure":
            root = "/nix/store/" + parts[1]
            if root not in records:
                raise ValueError("file inventory undeclared root")
            indexed.setdefault(root, []).append(file)
    seeds = {}
    for interpreter in ("python", "node", "bash"):
        if interpreter not in packages:
            continue
        seeds[interpreter] = [bash] if interpreter == "bash" else [packages[interpreter]["out"], bash]
    if resolved_tools is not None:
        if not isinstance(resolved_tools, dict) or not set(resolved_tools) <= CAPABILITIES:
            raise ValueError("finite native capability map required")
        for name, executable in resolved_tools.items():
            if (not isinstance(executable, str) or len(executable) > 4096
                    or not re.fullmatch(STORE + r"/[A-Za-z0-9._+/-]+", executable)
                    or any(part in {"", ".", ".."} for part in executable.split("/")[1:])):
                raise ValueError("canonical native executable required")
            root = "/".join(executable.split("/")[:4])
            alias = "closure/" + executable[len("/nix/store/"):]
            if root not in records or alias not in files:
                raise ValueError("native executable must be registered and inventoried")
            seeds[name] = [root, bash]
    query_tools = None
    # Bazel is the explicit feature declaration; Git-only host manifests stay valid.
    if "bazel" in packages:
        if not all(name in packages and isinstance(packages[name], dict)
                   and set(packages[name]) == {"out"} for name in QUERY_PACKAGES):
            raise ValueError("complete metadata query packages required")
        roots = [packages[name]["out"] for name in QUERY_PACKAGES]
        if any(not isinstance(root, str) or not re.fullmatch(STORE, root) for root in roots):
            raise ValueError("metadata query package root syntax")
        tools = {"bazel": roots[0] + "/bin/bazel", "bash": roots[1] + "/bin/bash",
                 "coreutils": roots[2] + "/bin/env", "python": roots[3] + "/bin/python3",
                 "git": roots[4] + "/bin/git"}
        if any("closure/" + executable[len("/nix/store/"):] not in files
               for executable in tools.values()):
            raise ValueError("metadata query executable not inventoried")
        seeds[QUERY_GROUP] = roots
        query_tools = {"schemaVersion": 1, "kind": "omux-codex-metadata-query-tools-v1",
                       "tools": tools, "path": [root + "/bin" for root in roots[1:5]],
                       "java_home": roots[5]}
    groups = {}
    for name, selected_seeds in seeds.items():
        roots = reachable(records, selected_seeds)
        if any(not indexed.get(root) for root in roots):
            raise ValueError("interpreter dependency has no inventoried files")
        selected = sorted(file for root in roots for file in indexed[root])
        serialized = "".join("\n".join(records[root]["record"]) + "\n" for root in roots)
        groups[name] = {"roots": roots, "files": selected, "registration": serialized}
    result = {"schemaVersion": 1, "groups": groups}
    if query_tools is not None:
        query_tools["roots"] = groups[QUERY_GROUP]["roots"]
        result["query_tools"] = query_tools
    return result


def bounded_read(path, bound):
    with Path(path).open("rb") as reader:
        data = reader.read(bound + 1)
    if len(data) > bound:
        raise ValueError("metadata size bound")
    return data.decode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("native", "store-paths", "registration", "inventory"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--resolved-tools")
    args = parser.parse_args()
    try:
        report = select(json.loads(bounded_read(args.native, 2 * 1024 * 1024)),
                        bounded_read(args.store_paths, 1024 * 1024).splitlines(),
                        bounded_read(args.registration, 4 * 1024 * 1024),
                        json.loads(bounded_read(args.inventory, 128 * 1024 * 1024)),
                        json.loads(bounded_read(args.resolved_tools, 64 * 1024)) if args.resolved_tools else None)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError):
        print(json.dumps({"passed": False, "gate": "declared-interpreter-closure-invalid"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
