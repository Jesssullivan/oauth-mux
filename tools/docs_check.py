"""Check the current authority graph using only declared Bazel runfiles.

Historical evidence retains its original bytes and obsolete links. Current
contracts must stay classified, resolve their links and retain stable acceptance
IDs. This guard makes no provider calls and cannot establish product support.
"""

import datetime as dt
from collections import Counter
import json
import os
from pathlib import Path
import re
import shlex
import sys
from urllib.parse import unquote, urlsplit


class ContractError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise ContractError(message)


def load_json(root, path):
    return json.loads((root / path).read_text())


def relative_link(source, destination):
    url = urlsplit(destination.strip().strip("<>"))
    if url.scheme or url.netloc or not url.path:
        return None
    path = unquote(url.path)
    require(not path.startswith("/"), f"{source}: absolute local link {path}")
    normalized = os.path.normpath(str(Path(source).parent / path))
    require(not normalized.startswith("../"), f"{source}: link leaves repository")
    return normalized


def retired_execution(line):
    line = line.strip()
    if line.startswith("$"):
        line = line[1:].strip()
    if not line or line.startswith("#"):
        return False
    try:
        tokens = shlex.split(line)
    except ValueError:
        return False  # A continued shell example is checked on each line.
    while tokens:
        token = tokens[0]
        if re.match(r"[A-Za-z_][A-Za-z0-9_]*=", token):
            tokens.pop(0)
        elif token in {"env", "command", "exec", "sudo"}:
            tokens.pop(0)
            while tokens and tokens[0].startswith("-"):
                option = tokens.pop(0)
                if option in {"-u", "--unset", "-C", "--chdir", "-g", "--group", "--user"} and tokens:
                    tokens.pop(0)
        elif token == "nix" and "--command" in tokens:
            tokens = tokens[tokens.index("--command") + 1:]
        else:
            break
    if not tokens:
        return False
    if tokens[0] in {"bash", "sh"} and "-c" in tokens:
        position = tokens.index("-c") + 1
        return position < len(tokens) and retired_execution(tokens[position])
    executable = tokens[0]
    return (Path(executable).name == "just" or
            (Path(executable).name == "zig" and tokens[1:2] == ["build"]) or
            executable.startswith(("scripts/", "./scripts/")))


def check_graph(root, manifest):
    require(manifest["schema_version"] == 1, "unsupported authority schema")
    current = manifest["current"]
    require(len(current) == len(set(current)), "duplicate current document")
    require(manifest["architecture"] in current, "architecture is not current")
    inventory = (root / manifest["historical_inventory"]).read_text()
    retained = set(re.findall(r"^\| `([^`]+)` \| Retained", inventory, re.M))
    deleted = set(re.findall(r"^\| `([^`]+)` \| Deleted", inventory, re.M))
    historical = retained | set(manifest["historical_extra"])
    require(not historical.intersection(current), "historical/current overlap")
    for path in current + sorted(historical):
        require((root / path).is_file(), f"missing classified document: {path}")
    for path in deleted:
        require(not (root / path).exists(), f"retired document returned: {path}")
    for file in (root / "docs").rglob("*.md"):
        path = str(file.relative_to(root))
        classified = path in current or path in historical or any(
            path.startswith(prefix) for prefix in manifest["historical_prefixes"]
        )
        require(classified, f"unclassified document: {path}")

    links = 0
    for source in current:
        body = (root / source).read_text()
        for destination in re.findall(r"\]\(([^\n)]+)\)", body):
            path = relative_link(source, destination)
            if path is not None:
                require((root / path).exists(), f"{source}: missing link target {path}")
                links += 1
        # Historical command quotations remain allowed in prose. Current shell
        # examples cannot restore retired execution entrypoints.
        for fence in re.findall(r"```(?:bash|sh|shell|console|text)?\n(.*?)```", body, re.S):
            for line in fence.splitlines():
                require(not retired_execution(line),
                        f"{source}: retired executable example: {line}")
    return len(current), len(historical), links


def check_acceptance(root, manifest):
    declarations = {}
    patterns = []
    for family in manifest["acceptance_families"]:
        path, pattern = family["path"], family["pattern"]
        patterns.append(pattern)
        body = (root / path).read_text()
        ids = re.findall(r"^(?:\|\s*|)`?(" + pattern + r")\b", body, re.M)
        require(ids, f"{path}: no acceptance declarations")
        require(len(ids) == len(set(ids)), f"{path}: duplicate acceptance IDs")
        require(set(ids) == set(family["ids"]), f"{path}: stable acceptance inventory changed")
        for item in ids:
            require(item not in declarations, f"duplicate declaration {item}")
            declarations[item] = path
    for decision in manifest["decisions"]:
        path, item = decision["path"], decision["id"]
        require(path in manifest["current"], f"decision is not current: {path}")
        require((root / path).read_text().startswith("# " + item + " "),
                f"{path}: stable ADR identifier changed")
        require(item not in declarations, f"duplicate decision ID {item}")
        declarations[item] = path
    patterns.append("ADR-[0-9]+")
    matcher = re.compile(r"\b(?:" + "|".join(patterns) + r")\b")
    for source in manifest["current"]:
        for item in matcher.findall((root / source).read_text()):
            require(item in declarations, f"{source}: undeclared acceptance {item}")
    return len(declarations)


def check_evidence(root, name, entry):
    evidence = entry["evidence"]
    require(isinstance(evidence, list) and evidence, f"{name}: completion without evidence")
    for record in evidence:
        require(isinstance(record, dict), f"{name}: unstructured evidence")
        require(record.get("kind") in {"document", "tracker_readback", "local_check"},
                f"{name}: unknown evidence class")
        path = record.get("path", "")
        require(path and not Path(path).is_absolute() and ".." not in Path(path).parts
                and (root / path).is_file(), f"{name}: nonexistent/nonportable evidence {path}")
        if record["kind"] == "local_check":
            require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                                 record.get("invocation_id", "")) is not None,
                    f"{name}: missing invocation ID")
            require(record.get("result") == "passed" and
                    record.get("command", "").startswith((
                        "nix develop --command bazelisk ",
                        "nix develop --ignore-environment --keep HOME --command bazelisk ",
                        "nix --option eval-cache false develop --ignore-environment --keep HOME --command bazelisk ",
                    )),
                    f"{name}: undeclared/unpassed local check")
            require(record["invocation_id"] in (root / path).read_text(),
                    f"{name}: invocation absent from referenced receipt")


def check_milestones(root, manifest):
    ledger = load_json(root, manifest["milestone_ledger"])
    require(ledger["schema_version"] == 1, "unsupported checkpoint schema")
    require(ledger["authority"] in manifest["current"], "checkpoint authority missing")
    require(ledger["automatic_dispatch"] is False, "checkpoint ledger invents dispatch")
    require(ledger["independent_active_goals"] is False, "four independent active goals")
    start = dt.datetime.fromisoformat(ledger["start"])
    require(start.utcoffset() == dt.timedelta(0), "start must be UTC")
    entries = {entry["id"]: entry for entry in ledger["milestones"]}
    require(len(entries) == len(ledger["milestones"]) == 4, "duplicate/missing milestones")
    for name, hours in (("h3", 3), ("h5", 5), ("h10", 10)):
        require(name in entries, f"missing checkpoint {name}")
        due = dt.datetime.fromisoformat(entries[name]["due"])
        require(due == start + dt.timedelta(hours=hours), f"incorrect deadline {name}")
    require("weekend" in entries, "weekend checkpoint missing")
    weekend = dt.datetime.fromisoformat(entries["weekend"]["due"])
    require(weekend > dt.datetime.fromisoformat(entries["h10"]["due"]), "weekend order")
    # This ledger records the explicitly selected October EDT weekend. Fixed
    # offset avoids reading a host timezone database inside a declared action.
    local = weekend.astimezone(dt.timezone(dt.timedelta(hours=-4)))
    require(ledger["timezone"] == "America/New_York" and local.weekday() == 6
            and (local.hour, local.minute, local.second) == (23, 59, 0),
            "weekend deadline must be Sunday 23:59 EDT")
    for name, entry in entries.items():
        require(entry["status"] in {"planned", "in_progress", "passed", "blocked", "unrun"},
                f"invalid status {name}")
        expected = {"h3": [], "h5": ["h3"], "h10": ["h3", "h5"], "weekend": ["h10"]}
        require(entry.get("depends_on", []) == expected[name], f"{name}: required dependency changed")
        for dependency in entry.get("depends_on", []):
            require(dependency in entries and dependency != name, f"invalid dependency {name}")
            require(dt.datetime.fromisoformat(entries[dependency]["due"])
                    < dt.datetime.fromisoformat(entry["due"]), f"cyclic/out-of-order dependency {name}")
            if entry["status"] == "passed":
                require(entries[dependency]["status"] == "passed", f"{name}: unmet dependency")
        if entry["status"] == "passed":
            check_evidence(root, name, entry)
    return len(entries)


def check_tracker(root, manifest):
    contract = manifest["tracker_receipt"]
    tracker = load_json(root, contract["path"])
    counts = Counter(record["kind"] for record in tracker["receipts"])
    require(dict(counts) == contract["expected_kinds"], "tracker receipt disposition/count drift")
    verification = tracker["verification"]
    require(verification["mismatches"] == [] and
            verification["readbackRecords"] == len(tracker["after"]), "tracker readback mismatch")
    records = {record["id"]: record for record in tracker["after"]}
    require(len(records) == len(tracker["after"]), "duplicate tracker readback")
    for item, status in contract["unchanged_issue_statuses"].items():
        require(records[item]["status"] == status, f"historical ticket status changed: {item}")
    for item in contract["canceled_issue_ids"]:
        require(records[item]["status"] == "Canceled", f"cancellation mismatch: {item}")
    for item in contract["new_issue_ids"]:
        require(records[item]["status"] == "Todo", f"unproved gap promoted: {item}")
    for item in ("P-TIN-107", "P-TIN-101"):
        status = records[item]["status"]
        if isinstance(status, dict):
            status = status.get("name")
        require(status == "Canceled", f"deferred project resurrected: {item}")

    declarations = {item for family in manifest["acceptance_families"] for item in family["ids"]}
    declarations.update(item["id"] for item in manifest["decisions"])
    pattern = r"\b(?:" + "|".join(family["pattern"] for family in manifest["acceptance_families"]) + r"|ADR-[0-9]+)\b"
    for mutation in tracker["receipts"]:
        description = mutation.get("requested", {}).get("description", "")
        current = re.split(r"(?m)^## (?:Historical|Preserved)", description, maxsplit=1)[0]
        for item in re.findall(pattern, current):
            require(item in declarations, f"tracker references unknown acceptance {item}")
    milestone_records = {item["id"]: item for item in tracker["milestoneAfter"]}
    ledger = load_json(root, manifest["milestone_ledger"])
    for entry in ledger["milestones"]:
        item = milestone_records.get(entry["linear_milestone_id"])
        require(item is not None, f"{entry['id']}: missing Linear milestone readback")
        require(item["targetDate"].startswith(entry["local_date"]),
                f"{entry['id']}: Linear checkpoint date drift")
    return sum(counts.values())


def check_sprints(root, manifest):
    """Independent implementation checkpoints cannot reuse ratification proof."""
    ledgers = manifest.get("sprint_ledgers", [])
    require(len(ledgers) == len(set(ledgers)), "duplicate sprint ledger")
    count = 0
    for path in ledgers:
        require(not Path(path).is_absolute() and ".." not in Path(path).parts,
                "nonportable sprint ledger")
        ledger = load_json(root, path)
        require(ledger["schema_version"] == 1 and
                ledger["kind"] == "implementation_sprint_checkpoint", "unsupported sprint schema")
        require(ledger["authority"] in manifest["current"], "sprint authority missing")
        require(ledger["automatic_dispatch"] is False and
                ledger["independent_active_goals"] is False, "sprint invents dispatch")
        start, due = (dt.datetime.fromisoformat(ledger[key]) for key in ("start", "due"))
        require(start.utcoffset() == due.utcoffset() == dt.timedelta(0), "sprint dates must be UTC")
        require(type(ledger["duration_hours"]) is int and ledger["duration_hours"] > 0 and
                due == start + dt.timedelta(hours=ledger["duration_hours"]), "incorrect sprint deadline")
        allowed = {"planned", "in_progress", "passed", "blocked", "unrun"}
        require(ledger["status"] in allowed, "invalid sprint status")
        entries = ledger["acceptance"]
        require(entries and len({entry["id"] for entry in entries}) == len(entries),
                "duplicate/missing sprint acceptance")
        for entry in entries:
            require(entry["status"] in allowed, "invalid sprint acceptance status")
            require(entry.get("issues") and all(re.fullmatch(r"TIN-[0-9]+", item)
                    for item in entry["issues"]), "missing sprint tracker scope")
            if entry["status"] == "passed":
                check_evidence(root, entry["id"], entry)
            elif entry["status"] in {"blocked", "unrun"}:
                require(entry.get("next_action"), "sprint gate lacks next action")
        if ledger["status"] == "passed":
            require(all(entry["status"] == "passed" for entry in entries),
                    "sprint passed with incomplete acceptance")
            check_evidence(root, path, ledger)
        require(ledger.get("claim") == "experimental_unshipped_live_continuity_unavailable",
                "sprint checkpoint promotes support")
        count += 1
    return count


def main():
    # __file__ retains the runfiles path under the declared Python launcher.
    root = Path(__file__).absolute().parent.parent
    manifest = load_json(root, "docs/authority.json")
    current, historical, links = check_graph(root, manifest)
    ids = check_acceptance(root, manifest)
    checkpoints = check_milestones(root, manifest)
    mutations = check_tracker(root, manifest)
    sprints = check_sprints(root, manifest)
    print(f"authority: {current} current, {historical} historical, {links} local links; "
          f"{ids} acceptance IDs; {checkpoints} checkpoints; {sprints} implementation sprints; {mutations} historical tracker mutations")


if __name__ == "__main__":
    try:
        main()
    except (ContractError, KeyError, ValueError, OSError) as error:
        print(f"documentation contract: {error}", file=sys.stderr)
        sys.exit(1)
