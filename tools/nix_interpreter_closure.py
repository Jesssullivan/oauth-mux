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
CAPABILITIES = frozenset(("dbus_run_session", "dbus_daemon", "gnome_keyring_daemon",
                          "patchelf", "openssl_tool", "systemctl", "moc", "rcc", "uic", "secret_tool"))


def registrations(text, declared):
    if len(text) > 4 * 1024 * 1024:
        raise ValueError("registration bound")
    if not declared or len(declared) > MAX_RECORDS or len(set(declared)) != len(declared):
        raise ValueError("declared root set")
    if any(not re.fullmatch(STORE, root) for root in declared):
        raise ValueError("declared root syntax")
    lines = text.splitlines()
    records, cursor = {}, 0
    while cursor < len(lines):
        if len(records) >= MAX_RECORDS or cursor + 5 > len(lines):
            raise ValueError("registration shape")
        root, nar_hash, size, deriver, count = lines[cursor:cursor + 5]
        if (not re.fullmatch(STORE, root) or root in records
                or not re.fullmatch(r"sha256:(?:[0-9abcdfghijklmnpqrsvwxyz]{52}|[0-9a-f]{64})", nar_hash)
                or not re.fullmatch(r"[1-9][0-9]{0,18}", size)
                or not re.fullmatch(r"[0-9]{1,4}", count)
                or (deriver and not re.fullmatch(STORE + r"\.drv", deriver))):
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
                or any(not re.fullmatch(STORE, ref) for ref in references)):
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
    groups = {}
    for name, selected_seeds in seeds.items():
        roots = reachable(records, selected_seeds)
        if any(not indexed.get(root) for root in roots):
            raise ValueError("interpreter dependency has no inventoried files")
        selected = sorted(file for root in roots for file in indexed[root])
        serialized = "".join("\n".join(records[root]["record"]) + "\n" for root in roots)
        groups[name] = {"roots": roots, "files": selected, "registration": serialized}
    return {"schemaVersion": 1, "groups": groups}


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
