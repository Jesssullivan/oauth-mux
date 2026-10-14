"""Retained public SDK tree proof core; mutable private proposal, UNRUN.

Parsing supplies expected facts, never producer/admission/execution authority.
A production constructor must separately authenticate the declared successful
creator and hold its complete inputs. Old carrier Root and stream rules stay
unchanged; canonical logical mode and actual retained physical mode are distinct.
"""
from types import MappingProxyType
import os
import codex_native_sdk_carrier as core

INVENTORY_KIND = "omux-retained-public-sdk-tree-manifest-v1"
REPORT_KIND = "omux-retained-public-sdk-tree-producer-v1"
PHYSICAL_POLICY = "bazel-retained-sdk-all-regular-0555-v1"
TARGET = "//tools:codex_native_retained_sdk_tree_producer"
PROFILE = "native-sdk-tree-producer-reserved"


def parse_inventory(raw, selected_sha256, clock):
    """Bounded canonical expected-content facts, not an admission token."""
    clock.tick()
    core.need(type(raw) is bytes and 0 < len(raw) <= core.MAX_METADATA,
              "sdk-tree-inventory-size")
    core.need(core.sha(raw) == core.digest(selected_sha256), "sdk-tree-inventory-pin")
    value = core.decode(raw)
    core.need(type(value) is dict and set(value) == {
        "schema_version", "kind", "carrier", "nars", "entries"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["kind"] == INVENTORY_KIND and core.encoded(value) == raw,
        "sdk-tree-inventory-shape")
    lineage = value["carrier"]
    core.need(type(lineage) is dict and set(lineage) == {
        "receipt_sha256", "manifest_sha256", "payload_sha256", "origin_receipt_sha256"},
        "sdk-tree-inventory-lineage")
    for pin in lineage.values(): core.digest(pin)
    nars = value["nars"]
    core.need(type(nars) is dict and set(nars) == {"sdk", "jdk"}, "sdk-tree-nar-roles")
    for selected in nars.values():
        clock.tick()
        core.need(type(selected) is dict and set(selected) == {
            "narHash", "narSize", "linkTargetsFollowed", "executionAuthority"}
            and type(selected["narHash"]) is str and selected["narHash"].startswith("sha256:")
            and type(selected["narSize"]) is int and 0 < selected["narSize"] <= core.MAX_BYTES
            and selected["linkTargetsFollowed"] is False
            and selected["executionAuthority"] is False, "sdk-tree-nar-shape")
        core.digest(selected["narHash"][7:])
    entries = value["entries"]
    core.need(type(entries) is list and 0 < len(entries) <= core.MAX_ENTRIES,
              "sdk-tree-entry-bound")
    logical, previous, total = {}, None, 0
    for entry in entries:
        clock.tick()
        core.need(type(entry) is dict and "role" in entry and "path" in entry
            and "kind" in entry and entry["role"] in ("sdk", "jdk"), "sdk-tree-entry-role")
        role, name = entry["role"], entry["path"]
        parts = core.relative(name, empty=True)
        key = (role, name)
        core.need(key not in logical and (previous is None or previous < key),
                  "sdk-tree-entry-order-duplicate")
        previous = key
        base = {"role", "path", "kind"}
        if entry["kind"] == "directory":
            core.need(set(entry) == base | {"mode"} and type(entry["mode"]) is int
                and entry["mode"] == 0o555, "sdk-tree-directory-shape")
            row = {"kind": "directory", "mode": 0o555}
        elif entry["kind"] == "file":
            core.need(parts != [] and set(entry) == base | {"mode", "size", "sha256"}
                and type(entry["mode"]) is int and entry["mode"] in (0o400, 0o444, 0o555)
                and type(entry["size"]) is int and 0 <= entry["size"] <= core.sdk.MAX_FILE,
                "sdk-tree-file-shape")
            core.digest(entry["sha256"])
            total += entry["size"]
            core.need(total <= core.MAX_BYTES, "sdk-tree-byte-bound")
            row = {field: entry[field] for field in ("kind", "mode", "size", "sha256")}
        else:
            core.need(parts != [] and entry["kind"] == "symlink"
                and set(entry) == base | {"target"} and type(entry["target"]) is str
                and 0 < len(os.fsencode(entry["target"])) <= 65536
                and not any(ord(character) < 32 or ord(character) == 127 for character in entry["target"]),
                "sdk-tree-link-shape")
            row = {"kind": "symlink", "target": entry["target"]}
        if parts:
            parent = (role, "/".join(parts[:-1]))
            core.need(parent in logical and logical[parent]["kind"] == "directory",
                      "sdk-tree-entry-parent")
        else:
            core.need(row["kind"] == "directory", "sdk-tree-role-root")
        logical[key] = MappingProxyType(row)
    core.need(all((role, "") in logical for role in ("sdk", "jdk")), "sdk-tree-missing-role")
    clock.tick()
    return MappingProxyType(logical), core.encoded(nars), core.encoded(lineage)


def physical_expected(logical, policy, clock):
    """Derived physical facts only; caller must own authenticated logical facts."""
    core.need(policy == PHYSICAL_POLICY, "sdk-tree-physical-policy")
    result = {}
    for key, row in logical.items():
        clock.tick()
        result[key] = MappingProxyType({**row, "mode": 0o555}) if row["kind"] == "file" else row
    clock.tick()
    return MappingProxyType(result)


def scan_retained_tree(roots, logical, policy, clock):
    """Full actual-byte proof; old exact physical stream predicates unchanged.

    This function accepts expected facts, not a successful-creator certificate.
    Only the separately sealed production admission path may use its result.
    """
    core.need(set(roots) == {"sdk", "jdk"} and all(type(root) is core.Root
        and root.clock is clock and root.owned is False for root in roots.values()),
        "sdk-tree-exact-current-roots")
    physical = physical_expected(logical, policy, clock)
    witnesses = core._fresh_namespace(roots, physical, clock)
    observed = {key: dict(row) for key, row in physical.items()}
    completed, aggregate, nars = set(), [0], {}
    for role in sorted(roots):
        with core._FreshNarParents(roots[role], clock) as parents:
            def opener(unused, name, selected=role):
                key = (selected, name)
                core.need(key in physical and physical[key]["kind"] == "file",
                          "sdk-tree-stream-selected")
                return core._FreshNarFile(roots[selected], name, physical[key], witnesses,
                    selected, observed, completed, aggregate, clock, parents)
            # Physical0555 is required by the original stream. The executable
            # bit serialized in canonical NAR comes from authenticated logical
            # membership, not the retained physical executable bit.
            nars[role] = core.nar.hash_descriptor(core.descriptor(role, logical, clock),
                opener=opener, deadline=clock.deadline)
            roots[role].check()
    core.need(observed == physical and len(completed) == sum(
        row["kind"] == "file" for row in logical.values()) and aggregate[0] == sum(
        row.get("size", 0) for row in logical.values()), "sdk-tree-complete-stream")
    core.need(core._fresh_namespace(roots, physical, clock) == witnesses,
              "sdk-tree-final-complete-namespace")
    for root in roots.values(): root.check()
    clock.tick()
    return witnesses, core.encoded(nars)


def inventory_document(carrier_pin, report, nars, logical, clock):
    """Creator output from a fully authenticated held carrier binding only.

    It is a portable expected-content document. The separate genuine creator
    admission/outer success and current consumer proof are still mandatory.
    """
    clock.tick()
    lineage = {"receipt_sha256": core.digest(carrier_pin),
        "manifest_sha256": report["manifest_sha256"],
        "payload_sha256": report["payload_sha256"],
        "origin_receipt_sha256": report["origin"]["receipt_sha256"]}
    entries = []
    for (role, name), row in sorted(logical.items()):
        clock.tick()
        entries.append({"role": role, "path": name, **row})
    raw = core.encoded({"schema_version": 1, "kind": INVENTORY_KIND,
        "carrier": lineage, "nars": nars, "entries": entries})
    # Use the same strict closed shape for publication and consumer facts.
    actual, actual_nars, actual_lineage = parse_inventory(raw, core.sha(raw), clock)
    core.need(actual == logical and actual_nars == core.encoded(nars)
        and actual_lineage == core.encoded(lineage), "sdk-tree-manifest-roundtrip")
    clock.tick()
    return raw
