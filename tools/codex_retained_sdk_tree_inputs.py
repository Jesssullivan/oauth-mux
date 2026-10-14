"""Held retained SDK-tree evidence; private coauthor draft, UNRUN.

CAS/tree bytes, parser results and prior creator success are distinct facts.
Only the closed declared-input and live artifact-owner factory may admit them.
No raw paths, caller clock tuple or success Boolean creates that owner.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import threading
import time
from types import MappingProxyType
import xml.etree.ElementTree as ET

import codex_native_sdk_carrier as core

TARGET = "//tools:codex_native_retained_sdk_tree_producer"
PROFILE = "native-sdk-tree-producer-reserved"
SELECTION_KIND = "omux-retained-public-sdk-tree-selection-v1"
RECIPE_KIND = "omux-retained-public-sdk-tree-recipe-v1"
PROOF_KIND = "omux-retained-public-sdk-tree-proof-inputs-v1"
CONFIG = "_main/integrations/codex-upstream/native-retained-sdk-tree-inputs.json"
DATA = "_main/tools/retained-sdk-tree-data.json"
BASE = "_main/tools/codex_native_retained_sdk_tree_materialized/sdk-tree-public"
PROOF_REPOSITORY = "omux_retained_public_sdk_tree_proof_inputs"
ROLES = ("outer_receipt", "test_evidence", "test_log", "test_xml", "program_receipt", "selected_inventory", "selected_recipe", "selected_creator_context", "qualification_confirmation")
ALIASES = {role: "proof/" + name for role, name in zip(ROLES, (
    "outer-receipt.json", "test-evidence.json", "test-log.evidence", "test-xml.evidence",
    "program-receipt.json", "selected-inventory.json", "selected-recipe.json", "selected-creator-context.json", "qualification-confirmation.json"))}
POLICY = "bazel-retained-sdk-all-regular-0555-v1"
OUTPUTS = ("tree", "receipt.json", "inventory.json", "recipe.json", "creator-context.json")
MAX_PROOF = 64 * 1024 * 1024
MAX_SMALL = 65536
_SEAL = object()


def need(value, reason):
    core.need(value, "retained-tree-" + reason)


def _pin_row(row, maximum):
    need(type(row) is dict and set(row) == {"path", "sha256", "bytes"}
         and type(row["bytes"]) is int and 0 < row["bytes"] <= maximum, "pin-row")
    core.absolute(row["path"])
    core.digest(row["sha256"])
    return row


def _context(value):
    keys = ("MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256", "BOOT_ID")
    need(type(value) is dict and set(value) == set(keys)
         and all(type(item) is str for item in value.values()) and value["MODE"] == PROFILE,
         "creator-context")
    need(all(re.fullmatch(r"[1-9][0-9]{0,19}", value[k]) is not None
             for k in ("ENTRY_NS", "DEADLINE_NS")), "creator-integers")
    entry, until = int(value["ENTRY_NS"]), int(value["DEADLINE_NS"])
    need(until - entry == 1200 * 10**9, "creator-original-envelope")
    need(re.fullmatch(r"(?:/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005|"
         r"/home/jess/\.local/state/omux-execution-20261005)/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
         value["EPOCH"]) is not None and re.fullmatch(r"[0-9a-f]{40}", value["SOURCE_COMMIT"]) is not None,
         "creator-epoch-source")
    core.digest(value["GRAPH_SHA256"])
    need(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["BOOT_ID"]) is not None, "creator-boot-domain")
    # Prior creator time is provenance, never a fresh consumer allowance.
    return entry, until


def current_creator_domain(raw, creator_context):
    """Authenticate declared current-domain bytes; never read host state here."""
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "current-clock-domain-bound")
    doc = core.decode(raw)
    need(type(doc) is dict and set(doc) == {"schema_version", "kind", "clock", "boot_id"}
         and type(doc["schema_version"]) is int and doc["schema_version"] == 1
         and doc["kind"] == "omux-sdk-tree-current-clock-domain-v1"
         and doc["clock"] == "linux-CLOCK_MONOTONIC"
         and type(doc["boot_id"]) is str
         and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", doc["boot_id"]) is not None,
         "current-clock-domain-shape")
    need(doc["boot_id"] == os.environ.get("OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID"), "current-clock-domain-input")
    need(doc["boot_id"] == creator_context["BOOT_ID"], "creator-clock-domain-changed")
    return doc


def selection(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SMALL, "selection-bound")
    doc = core.decode(raw)
    need(type(doc) is dict and set(doc) == {"schema_version", "kind", "status", "selection"}
         and type(doc["schema_version"]) is int and doc["schema_version"] == 1
         and doc["kind"] == SELECTION_KIND, "selection-shape")
    if doc["status"] == "UNSELECTED":
        need(doc["selection"] is None, "unselected-tuple")
        raise ValueError("SDK carrier refused: retained-tree-unselected")
    need(doc["status"] == "SELECTED-SUCCESSFUL-CREATOR-CONTENT-ONLY", "selection-status")
    row = doc["selection"]
    need(type(row) is dict and set(row) == {"creator_context", "producer", "receipt", "inventory", "materialization", "confirmation"},
         "selection-fields")
    _context(row["creator_context"])
    producer = row["producer"]
    need(type(producer) is dict and set(producer) == {"receipt", "sha256", "source_commit", "graph_sha256"},
         "producer-pin")
    need(producer["receipt"] == row["creator_context"]["EPOCH"] + "/receipt.json"
         and producer["source_commit"] == row["creator_context"]["SOURCE_COMMIT"]
         and producer["graph_sha256"] == row["creator_context"]["GRAPH_SHA256"], "producer-context-pin")
    core.digest(producer["sha256"])
    _pin_row(row["receipt"], MAX_SMALL)
    _pin_row(row["inventory"], core.MAX_METADATA)
    _pin_row(row["confirmation"], MAX_SMALL)
    need(row["confirmation"]["path"] == row["creator_context"]["EPOCH"] + "/sdk-tree-qualified.json",
         "selected-qualification-confirmation-path")
    need(Path(row["receipt"]["path"]).name == "receipt.json"
         and row["receipt"]["path"] == row["creator_context"]["EPOCH"] + "/sdk-tree-created/receipt.json"
         and Path(row["inventory"]["path"]) == Path(row["receipt"]["path"]).with_name("inventory.json"),
         "selected-output-members")
    material = row["materialization"]
    need(type(material) is dict and set(material) == {"recipe_sha256", "action_inputs_sha256"},
         "materialization-pins")
    for pin in material.values(): core.digest(pin)
    return core.encoded(row)


def recipe(raw, selected, clock):
    clock.tick()
    need(type(raw) is bytes and 0 < len(raw) <= core.MAX_METADATA, "recipe-bound")
    doc = core.decode(raw)
    need(core.encoded(doc) == raw and core.sha(raw) == selected["materialization"]["recipe_sha256"], "recipe-pin")
    need(type(doc) is dict and set(doc) == {"schema_version", "kind", "producer", "profile", "inputs", "outputs", "physical_mode_policy"}
         and type(doc["schema_version"]) is int and doc["schema_version"] == 1
         and doc["kind"] == RECIPE_KIND and doc["producer"] == TARGET and doc["profile"] == PROFILE
         and doc["outputs"] == list(OUTPUTS) and doc["physical_mode_policy"] == POLICY, "recipe-shape")
    inputs = doc["inputs"]
    need(type(inputs) is dict and set(inputs) == {"code", "tools", "proofs", "carrier"}, "recipe-inputs")
    count, total, paths = 0, 0, set()
    for role in ("code", "tools", "proofs"):
        rows = inputs[role]
        bound = 4096 if role == "code" else (64 if role == "proofs" else core.MAX_ENTRIES)
        need(type(rows) is list and 0 < len(rows) <= bound, "recipe-closure-bound")
        previous = None
        for row in rows:
            clock.tick()
            need(type(row) is dict and set(row) == {"path", "sha256", "bytes"}
                 and type(row["bytes"]) is int and 0 <= row["bytes"] <= core.MAX_METADATA, "recipe-input-row")
            core.relative(row["path"])
            core.digest(row["sha256"])
            need(previous is None or previous < row["path"], "recipe-closure-order")
            need(row["path"] not in paths, "recipe-disjoint-closure-paths")
            paths.add(row["path"])
            previous = row["path"]
            count += 1
            need(count <= core.MAX_ENTRIES, "recipe-complete-closure-bound")
            total += row["bytes"]
            need(total <= core.MAX_BYTES, "recipe-closure-byte-bound")
    need(count <= core.MAX_ENTRIES, "recipe-complete-closure-bound")
    rows = inputs["carrier"]
    need(type(rows) is list and len(rows) == 4, "recipe-carrier-four")
    for name, row in zip(core.FILES, rows):
        clock.tick()
        need(type(row) is dict and set(row) == {"name", "sha256", "bytes"} and row["name"] == name
             and type(row["bytes"]) is int and 0 < row["bytes"] <= core.MAX_BYTES, "recipe-carrier-row")
        core.digest(row["sha256"])
    need(core.sha(core.encoded(inputs)) == selected["materialization"]["action_inputs_sha256"], "recipe-input-digest")
    clock.tick()
    # This is a closed semantic input commitment, not a Bazel protobuf Action digest.
    return doc


class _Directory:
    """Metadata ancestry only; do not weaken the SDK's sealed exact Root type."""
    def __init__(self, path, clock):
        self.path, self.clock = core.absolute(path), clock
        self.chain, self.pending = [], None
        try:
            self.pending = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.chain.append((None, self.pending, core.identity(os.fstat(self.pending), True)))
            self.pending = None
            for part in self.path.parts[1:]:
                clock.tick()
                parent = self.fd
                before = os.stat(part, dir_fd=parent, follow_symlinks=False)
                need(stat.S_ISDIR(before.st_mode), "metadata-parent-type")
                self.pending = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                held = os.fstat(self.pending)
                selected = core.identity(held, True)
                need(core.identity(before, True) == selected == core.identity(
                    os.stat(part, dir_fd=parent, follow_symlinks=False), True), "metadata-parent-race")
                need(held.st_uid in (0, os.getuid()) and (not held.st_mode & 0o022 or bool(held.st_mode & stat.S_ISVTX)),
                     "metadata-ancestor-custody")
                self.chain.append((part, self.pending, selected))
                self.pending = None
            last = os.fstat(self.fd)
            need(stat.S_IMODE(last.st_mode) in (0o700, 0o555, 0o755)
                 and last.st_uid in (0, os.getuid()), "metadata-parent-mode")
            self.check()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: raise error from cleanup
            raise

    @property
    def fd(self): return self.chain[-1][1]

    def check(self):
        self.clock.tick()
        need(bool(self.chain) and self.pending is None, "metadata-ancestry-closed")
        for index, (name, fd, selected) in enumerate(self.chain):
            need(core.identity(os.fstat(fd), True) == selected, "metadata-held-ancestor")
            if index:
                need(core.identity(os.stat(name, dir_fd=self.chain[index - 1][1], follow_symlinks=False), True) == selected,
                     "metadata-named-ancestor")

    def close(self):
        entries, self.chain = self.chain, []
        pending, self.pending = self.pending, None
        first = None
        for unused, fd, witness in reversed(entries):
            if fd == pending: pending = None
            try: os.close(fd)
            except BaseException as error:
                if first is None: first = error
        if pending is not None:
            try: os.close(pending)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


class _Leaf:
    """Own actual nofollow parent ancestry and one FD before fallible reads."""
    def __init__(self, alias, clock, maximum, pin=None, expected_bytes=None, proof=False, declaration=False):
        self.alias, self.clock = core.absolute(alias), clock
        self.root = self.fd = self.alias_root = None
        self.closed = False
        self.maximum, self.expected_pin, self.expected_bytes = maximum, pin, expected_bytes
        need(type(maximum) is int and 0 < maximum <= core.MAX_METADATA, "leaf-bound")
        if pin is not None: core.digest(pin)
        try:
            clock.tick()
            self.path = self.alias.resolve(strict=True)
            self.alias_root = self._parent(self.alias.parent.resolve(strict=True))
            self.alias_parent_witness = core.identity(os.fstat(self.alias_root.fd))
            self.alias_witness = core.identity(os.stat(self.alias.name, dir_fd=self.alias_root.fd, follow_symlinks=False))
            need(stat.S_ISREG(self.alias_witness[4]) or stat.S_ISLNK(self.alias_witness[4]), "alias-kind")
            self.literal = os.readlink(self.alias.name, dir_fd=self.alias_root.fd) if stat.S_ISLNK(self.alias_witness[4]) else None
            self.root = self._parent(self.path.parent)
            self.parent_witness = core.identity(os.fstat(self.root.fd))
            before = os.stat(self.path.name, dir_fd=self.root.fd, follow_symlinks=False)
            modes = (0o444, 0o555, 0o600) if proof else ((0o444, 0o555, 0o644) if declaration else (0o444, 0o555))
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid in (0, os.getuid())
                 and stat.S_IMODE(before.st_mode) in modes
                 and 0 < before.st_size <= maximum, "leaf-custody")
            if stat.S_IMODE(before.st_mode) == 0o600: need(before.st_uid == os.getuid(), "private-proof-owner")
            self.witness = core.identity(before)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=self.root.fd)
            self.raw = self.read()
            self.check()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: raise error from cleanup
            raise

    def _parent(self, path):
        return _Directory(path, self.clock)

    def check(self):
        self.clock.tick()
        need(not self.closed and self.fd is not None, "leaf-closed")
        self.root.check()
        self.alias_root.check()
        need(core.identity(os.fstat(self.root.fd)) == self.parent_witness
             and core.identity(os.fstat(self.alias_root.fd)) == self.alias_parent_witness,
             "leaf-parent-witness")
        need(self.alias.resolve(strict=True) == self.path
             and self.alias.parent.resolve(strict=True) == self.alias_root.path
             and core.identity(os.stat(self.alias.name, dir_fd=self.alias_root.fd, follow_symlinks=False)) == self.alias_witness,
             "leaf-alias-race")
        if self.literal is not None: need(os.readlink(self.alias.name, dir_fd=self.alias_root.fd) == self.literal, "leaf-alias-text")
        need(core.identity(os.fstat(self.fd)) == self.witness == core.identity(
            os.stat(self.path.name, dir_fd=self.root.fd, follow_symlinks=False)), "leaf-held-name")
        self.clock.tick()

    def read(self):
        self.check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        blocks, size = [], 0
        while True:
            self.clock.tick()
            raw = os.read(self.fd, min(65536, self.maximum + 1 - size))
            if not raw: break
            size += len(raw)
            need(size <= self.maximum, "leaf-read-bound")
            blocks.append(raw)
        raw = b"".join(blocks)
        need(size == self.witness[6], "leaf-read-extent")
        if self.expected_pin is not None: need(core.sha(raw) == self.expected_pin, "leaf-read-pin")
        if self.expected_bytes is not None: need(size == self.expected_bytes, "leaf-selected-extent")
        self.check()
        return raw

    def close(self):
        self.closed = True
        fd, self.fd = self.fd, None
        root, self.root = self.root, None
        alias, self.alias_root = self.alias_root, None
        first = None
        for owned in (fd, root, alias):
            if owned is None: continue
            try:
                if type(owned) is int: os.close(owned)
                else: owned.close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first


def _success_xml(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PROOF and b"<!DOCTYPE" not in raw and b"<!ENTITY" not in raw,
         "xml-bound-declaration")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, LookupError):
        # Keep malformed selected bytes inside the closed redacted SOURCE
        # refusal union. Never export XML text/parser offsets or exception chain.
        raise ValueError("SDK carrier refused: retained-tree-xml-malformed") from None
    need(root.tag in ("testsuite", "testsuites"), "xml-root")
    suites = [root] if root.tag == "testsuite" else list(root)
    need(0 < len(suites) <= 4096 and all(s.tag == "testsuite" for s in suites), "xml-suites")
    for node in [root] + ([] if root.tag == "testsuite" else suites):
        for name in ("failures", "errors", "skipped"):
            value = node.get(name, "0")
            need(re.fullmatch(r"[0-9]{1,10}", value) is not None and int(value) == 0, "xml-counter")
    for suite in suites:
        value = suite.get("tests", "0")
        need(re.fullmatch(r"[0-9]{1,10}", value) is not None and int(value) > 0, "xml-positive-tests")
        need(not any(n.tag in ("failure", "error", "skipped") for n in suite.iter()), "xml-failed-child")


def _collector(index, outer, selected, held, target=TARGET):
    need(type(index) is dict and index.get("schema") == 1 and type(index.get("schema")) is int
         and type(index.get("bazel_exit")) is int and index["bazel_exit"] == 0
         and index.get("epoch_start_ns") == outer["epoch_start_ns"] and index.get("targets") == [target]
         and type(index.get("results")) is list and len(index["results"]) == 1, "index-success")
    row = index["results"][0]
    need(type(row) is dict and set(row) == {"target", "configuration", "state", "files"}
         and row["target"] == target and row["state"] == "observed"
         and type(row["configuration"]) is str and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", row["configuration"]) is not None,
         "index-result")
    files = row["files"]
    allowed = ("test.log", "test.xml", "test.outputs_manifest/MANIFEST", "test.outputs_manifest/ANNOTATIONS")
    need(type(files) is list and 2 <= len(files) <= 4, "index-file-bound")
    seen = set()
    for member in files:
        need(type(member) is dict and member.get("source") in allowed and member["source"] not in seen, "index-source")
        name = member["source"]
        seen.add(name)
        if member.get("state") == "copied":
            need(set(member) == {"source", "state", "file", "sha256", "bytes"}
                 and type(member["bytes"]) is int and 0 <= member["bytes"] <= MAX_PROOF, "copied-entry")
            filename = hashlib.sha256((target + "\0" + row["configuration"] + "\0" + name).encode()).hexdigest() + ".evidence"
            need(member["file"] == filename, "collector-name")
            core.digest(member["sha256"])
            if name in ("test.log", "test.xml"):
                role = "test_log" if name == "test.log" else "test_xml"
                leaf = held[role]
                need(member["bytes"] > 0 and leaf.path == Path(selected["producer"]["receipt"]).parent / "test-evidence" / filename
                     and core.sha(leaf.raw) == member["sha256"] and len(leaf.raw) == member["bytes"], "collector-held-pin")
        else:
            need(name not in ("test.log", "test.xml") and set(member) == {"source", "state", "bytes"}
                 and member["state"] in ("missing", "stale") and type(member["bytes"]) is int
                 and member["bytes"] == 0, "optional-diagnostic")
    need({"test.log", "test.xml"} <= seen and all(next(item for item in files if item["source"] == name)["state"] == "copied"
         for name in ("test.log", "test.xml")), "mandatory-log-xml")
    _success_xml(held["test_xml"].raw)


class AuthenticatedTreeInputs:
    """Current byte/proof owner; no parent lock, SDK execution or SOURCE claim."""
    def __init__(self, seal):
        need(seal is _SEAL, "private-constructor")
        self.leaves, self._roots = [], {}
        self.active, self.finished = True, False
        self.pid, self.thread = os.getpid(), threading.get_ident()

    @property
    def tree_root(self): return self._tree_root
    @property
    def inventory_raw(self): return self._inventory_raw
    @property
    def receipt_raw(self): return self._receipt_raw
    @property
    def logical(self): return self._logical
    @property
    def nars(self): return self._nars
    @property
    def roots(self): return MappingProxyType(self._roots)
    @property
    def witnesses(self): return self._witnesses

    def qualification_record(self):
        self.check()
        # Fresh detached metadata, never a serialized owner or proof verdict.
        return core.decode(self._qualification_raw)

    def _leaf(self, alias, maximum, pin=None, expected_bytes=None, proof=False, declaration=False):
        need(len(self.leaves) < 17, "metadata-owner-bound")
        leaf = _Leaf(alias, self.clock, maximum, pin, expected_bytes, proof, declaration)
        # A receiver slot remains owned even if its list enrollment fails.
        try: self.leaves.append(leaf)
        except BaseException as error:
            try: leaf.close()
            except BaseException as cleanup: raise error from cleanup
            raise
        return leaf

    def check(self):
        need(self.active and os.getpid() == self.pid and threading.get_ident() == self.thread
             and self.clock.deadline == self.deadline and self.clock.until_ns == self.until_ns,
             "current-owner-clock")
        self.clock.tick()
        need(type(self.alias_owner) is self._owner_type, "current-controls-type")
        need(self._source.DEADLINE == self.deadline, "same-source-admission-clock")
        self.alias_owner.fence()
        current = {name: os.environ.get("OMUX_NATIVE_FILE_WRITER_MODELS_" + name)
                   for name in self._context}
        need(core.encoded(current) == self._context_raw, "current-source-context")
        need(Path(os.environ.get("TEST_SRCDIR", "")).resolve(strict=True) == self.runfiles,
             "same-declared-runfiles-owner")
        for leaf in self.leaves: leaf.check()
        need(self.tree_alias.resolve(strict=True) == self._tree_root
             and self.tree_alias.parent.resolve(strict=True) == self.artifact_parent.path
             and core.identity(os.stat(self.tree_alias.name, dir_fd=self.artifact_parent.fd,
                                      follow_symlinks=False)) == self.tree_alias_witness,
             "current-declared-tree-alias")
        if self.tree_alias_literal is not None:
            need(os.readlink(self.tree_alias.name, dir_fd=self.artifact_parent.fd) == self.tree_alias_literal,
                 "current-declared-tree-link")
        self.artifact_parent.check()
        need(set(self._roots) == {"sdk", "jdk"}, "current-tree-role-owner")
        for role, root in self._roots.items():
            need(type(root) is core.Root and root.path == self._tree_root / role
                 and root.clock is self.clock and root.owned is False, "current-tree-root-owner")
            root.check()
        self.clock.tick()

    def fence(self):
        self.check()
        physical = self._proof_core.physical_expected(self._logical, POLICY, self.clock)
        actual = core._fresh_namespace(self._roots, physical, self.clock)
        need({key: tuple(row) for key, row in actual.items()} == self._witnesses,
             "current-full-namespace-witness")
        self.check()

    def full(self):
        """Reread bounded selected proof/recipe/manifest bytes, not cached verdicts."""
        self.check()
        for leaf in self.leaves:
            need(leaf.read() == leaf.raw, "current-proof-byte-readback")
        self.check()

    def finish(self):
        need(not self.finished, "one-final-proof")
        # Complete long provenance reads FIRST. The LAST SDK stream is current.
        self.full()
        actual, nars = self._proof_core.scan_retained_tree(self._roots, self._logical, POLICY, self.clock)
        need({key: tuple(row) for key, row in actual.items()} == self._witnesses and nars == self._nars,
             "last-full-tree-nar-witness")
        self.fence()
        self.finished = True
        self.clock.tick()

    def close(self):
        self.active = False
        leaves, self.leaves = self.leaves, []
        roots, self._roots = self._roots, {}
        parent = getattr(self, "artifact_parent", None)
        self.artifact_parent = None
        first = None
        for owned in roots.values():
            try: owned.close()
            except BaseException as error:
                if first is None: first = error
        for owned in reversed(leaves):
            try: owned.close()
            except BaseException as error:
                if first is None: first = error
        if parent is not None:
            try: parent.close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, exc_type, error, trace):
        try:
            if exc_type is None:
                need(self.finished, "successful-exit-requires-final")
                self.fence()
        except BaseException as refusal:
            try: self.close()
            except BaseException as cleanup: raise refusal from cleanup
            raise
        try: self.close()
        except BaseException as cleanup:
            if error is not None:
                prior = BaseException.__cause__.__get__(error)
                raise BaseException.with_traceback(error, trace) from (cleanup if prior is None else prior)
            raise
        if exc_type is None: self.clock.tick()

    def __copy__(self): raise ValueError("retained-tree-owner-not-transferable")
    def __deepcopy__(self, unused): raise ValueError("retained-tree-owner-not-transferable")
    def __reduce_ex__(self, unused): raise ValueError("retained-tree-owner-not-transferable")


def _layout(raw):
    value = core.decode(raw)
    need(type(value) is dict and set(value) == {"kind", "recipe", "creator_context", "artifact"}
         and value["kind"] == "omux-retained-public-sdk-tree-declared-data-v1"
         and value["recipe"] == BASE + "/recipe.json"
         and value["creator_context"] == BASE + "/creator-context.json"
         and value["artifact"] == {"root": BASE + "/tree", "receipt": BASE + "/receipt.json",
                                    "inventory": BASE + "/inventory.json"}, "fixed-declared-directory-layout")
    return value


def _mapped(runfiles, rows):
    need(type(rows) in (tuple, list) and 0 < len(rows) <= 4096, "mapping-bound")
    need(all(type(row) in (tuple, list) and len(row) == 3 and all(type(v) is str for v in row)
             for row in rows), "mapping-rows")
    names = [row[2] for row in rows if row[0] in ("", "_main") and row[1] == PROOF_REPOSITORY]
    need(len(names) == 1 and re.fullmatch(r"[A-Za-z0-9_+.-]{1,256}", names[0]) is not None,
         "single-proof-repository")
    return Path(runfiles) / names[0]


def _capture_proofs(owner, repository, selected):
    mapping = owner._leaf(repository / "sdk-tree-proof-inputs.json", MAX_SMALL)
    doc = core.decode(mapping.raw)
    need(type(doc) is dict and set(doc) == {"kind", "proofs"} and doc["kind"] == PROOF_KIND
         and type(doc["proofs"]) is dict and set(doc["proofs"]) == set(ROLES), "proof-mapping-shape")
    paths = set()
    held = {}
    for role in ROLES:
        row = doc["proofs"][role]
        need(type(row) is dict and set(row) == {"path", "sha256", "bytes", "alias"}
             and row["alias"] == ALIASES[role], "proof-role")
        maximum = MAX_SMALL if role == "qualification_confirmation" else (
            core.MAX_METADATA if role in ("selected_inventory", "selected_recipe") else MAX_PROOF)
        _pin_row({k: row[k] for k in ("path", "sha256", "bytes")}, maximum)
        need(row["path"] not in paths, "proof-path-duplicate")
        paths.add(row["path"])
        leaf = owner._leaf(repository / row["alias"], maximum,
                           row["sha256"], row["bytes"], proof=role not in ("selected_inventory", "selected_recipe", "selected_creator_context"))
        need(str(leaf.path) == row["path"], "proof-alias-target")
        held[role] = leaf
    need(str(held["outer_receipt"].path) == selected["producer"]["receipt"]
         and core.sha(held["outer_receipt"].raw) == selected["producer"]["sha256"]
         and str(held["program_receipt"].path) == selected["receipt"]["path"]
         and core.sha(held["program_receipt"].raw) == selected["receipt"]["sha256"]
         and len(held["program_receipt"].raw) == selected["receipt"]["bytes"]
         and str(held["selected_inventory"].path) == selected["inventory"]["path"]
         and core.sha(held["selected_inventory"].raw) == selected["inventory"]["sha256"]
         and len(held["selected_inventory"].raw) == selected["inventory"]["bytes"]
         and str(held["qualification_confirmation"].path) == selected["confirmation"]["path"]
         and core.sha(held["qualification_confirmation"].raw) == selected["confirmation"]["sha256"]
         and len(held["qualification_confirmation"].raw) == selected["confirmation"]["bytes"], "independent-selected-proof-pins")
    return held


def _qualify_creator(selected, held, receipt, inventory, recipe_doc):
    # The fixed guard policy is a separately declared code dependency. No caller
    # callback, reported clock or generic verify_caps Boolean replaces it.
    import guard_native_sdk_tree_reserved as guard
    import codex_protocol_history_native as protocol
    outer = core.decode(held["outer_receipt"].raw)
    context = selected["creator_context"]
    entry, until = _context(context)
    reserved = outer["native_sdk_tree_reservation"]
    need(type(reserved) is dict and reserved == guard.projection(PROFILE, entry, until, True, reserved["resident"]),
         "creator-actual-reservation")
    resident = reserved["resident"]
    need(type(resident) is dict and set(resident) == {"scope", "kernel_bounds", "observations",
        "initial_direct_processes_retained", "initial_direct_process_count", "outer_pid_namespace_matched",
        "hierarchical_caps", "descendant_process_inventory", "installation_qualified", "health_observed",
        "custody_observed", "resident_signalled", "whole_host_reservation"}
        and resident["scope"] == "sampled-fixed-default-cgroup-kernel-reservation-v1"
        and type(resident["observations"]) is int and 0 < resident["observations"] <= 65535
        and type(resident["initial_direct_process_count"]) is int and 0 < resident["initial_direct_process_count"] <= 32
        and all(resident[k] is True for k in ("initial_direct_processes_retained", "outer_pid_namespace_matched", "hierarchical_caps"))
        and all(resident[k] is False for k in ("descendant_process_inventory", "installation_qualified", "health_observed",
             "custody_observed", "resident_signalled", "whole_host_reservation")), "creator-resident-reservation")
    guard.kernel.kernel_bounds(resident["kernel_bounds"])
    need(resident["initial_direct_process_count"] <= int(resident["kernel_bounds"]["pids.max"]), "creator-resident-pids")
    need(outer["id"] == Path(context["EPOCH"]).name
         and outer["unit"] == "omux-execution-" + outer["id"] + ".service"
         and outer["manager"] == "system" and outer["profile"] == PROFILE
         and type(outer["exit"]) is int and outer["exit"] == 0
         and type(outer["workload_exit"]) is int and outer["workload_exit"] == 0
         and outer["controller_failure"] is None and outer["descendants_empty"] is True
         and outer["cleanup"]["state"] == "empty" and outer["cleanup"]["ownership"] == "verified"
         and type(outer["cleanup"]["readback_attempts"]) is int and outer["cleanup"]["readback_attempts"] >= 2
         and outer["source_dirty"] == "false" and outer["source_commit"] == context["SOURCE_COMMIT"]
         and outer["graph_sha256"] == context["GRAPH_SHA256"]
         and outer["verb"] == "test" and outer["targets"] == [TARGET]
         and outer["test_evidence"]["state"] == "preserved", "genuine-creator-success")
    observed = outer["observed_properties"]
    protocol.native.phase2_effective_runtime(observed["RuntimeMaxUSec"], 1170)
    need(all(observed.get(k) == v for k, v in {
        "MemoryMax": "4026531840", "MemorySwapMax": "0", "TasksMax": "480", "PrivateNetwork": "yes",
        "KillMode": "control-group", "SendSIGKILL": "yes", "OOMPolicy": "kill", "RemainAfterExit": "yes"}.items()),
        "creator-effective-caps")
    from decimal import Decimal
    token = observed.get("CPUQuotaPerSecUSec")
    match = re.fullmatch(r"([0-9]{1,7}(?:[.][0-9]{1,6})?)(us|ms|s)", token) if type(token) is str else None
    need(match is not None and Decimal(match[1]) * {"us": 1, "ms": 1000, "s": 1000000}[match[2]] == 1900000,
         "creator-effective-cpu")
    origin = guard.validate_artifact_origin(outer, context, selected["materialization"])
    need(type(origin) is dict, "typed-compatible-artifact-origin")
    # Canonical bytes alone are only artifact provenance. Actual held selected
    # confirmation separately authenticates the observed timely postcommit proof.
    confirmation = core.decode(held["qualification_confirmation"].raw)
    qualified = guard.validate_qualification_confirmation(outer, confirmation,
        core.sha(held["outer_receipt"].raw), len(held["outer_receipt"].raw))
    need(type(qualified) is dict and qualified == confirmation, "typed-qualification-confirmation")
    held["outer_receipt"].check()
    need(confirmation["canonical_receipt_creator_witness"] == held["outer_receipt"].witness,
         "same-confirmed-canonical-receipt-held-witness")
    held["qualification_confirmation"].check()
    need(held["test_evidence"].path == Path(context["EPOCH"]) / "test-evidence.json"
         and core.sha(held["test_evidence"].raw) == outer["test_evidence"]["sha256"], "actual-index-pin")
    index = core.decode(held["test_evidence"].raw)
    _collector(index, outer, selected, held)
    # The guard copies bounded products before publishing successful evidence.
    # Shared output-base test.outputs are never a historical metadata identity.
    expected = Path(context["EPOCH"]) / "sdk-tree-created/receipt.json"
    need(held["program_receipt"].path == expected and selected["receipt"]["path"] == str(expected),
         "immutable-creator-output-namespace")
    ledger = origin["created_metadata"]
    need(type(ledger) is list and len(ledger) == 4, "creator-metadata-ledger")
    for name, row in zip(("creator-context.json", "inventory.json", "receipt.json", "recipe.json"), ledger):
        need(type(row) is dict and set(row) == {"name", "path", "sha256", "bytes"}
             and row["name"] == name and row["path"] == str(Path(context["EPOCH"]) / "sdk-tree-created" / name)
             and type(row["bytes"]) is int and 0 < row["bytes"] <= core.MAX_METADATA, "creator-metadata-row")
        role = {"creator-context.json": "selected_creator_context", "inventory.json": "selected_inventory",
                "receipt.json": "program_receipt", "recipe.json": "selected_recipe"}[name]
        need(str(held[role].path) == row["path"] and core.sha(held[role].raw) == row["sha256"]
             and len(held[role].raw) == row["bytes"], "genuine-created-metadata-copy")
    need(core.sha(held["selected_recipe"].raw) == selected["materialization"]["recipe_sha256"]
         and core.decode(held["selected_creator_context"].raw) == context, "creator-recipe-context-copy")
    need(receipt == core.decode(held["program_receipt"].raw), "declared-receipt-equals-actual-creator")
    program_context = {"mode": PROFILE, "epoch": context["EPOCH"], "source_commit": context["SOURCE_COMMIT"],
                       "graph_sha256": context["GRAPH_SHA256"], "boot_id": context["BOOT_ID"], "entry_monotonic_ns": entry,
                       "deadline_monotonic_ns": until, "work_cutoff_monotonic_ns": entry + 1170 * 10**9}
    need(type(receipt) is dict and set(receipt) == {
        "schema_version", "kind", "producer", "producer_context", "inventory", "tree_root",
        "extraction_receipt_sha256", "physical_mode_policy", "created_tree_commitment", "carrier_qualification",
        "materialization", "sdk_execution_qualified", "source_qualified", "compiler_qualified", "runtime_qualified"}
        and type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
        and receipt["kind"] == "omux-retained-public-sdk-tree-producer-v1" and receipt["producer"] == TARGET
        and receipt["producer_context"] == program_context and receipt["tree_root"] == "tree"
        and receipt["physical_mode_policy"] == POLICY
        and receipt["inventory"] == {"sha256": selected["inventory"]["sha256"], "bytes": selected["inventory"]["bytes"]}
        and all(receipt[k] is False for k in ("sdk_execution_qualified", "source_qualified", "compiler_qualified", "runtime_qualified")),
        "creator-report-closed")
    need(all(type(receipt["producer_context"][key]) is int for key in (
        "entry_monotonic_ns", "deadline_monotonic_ns", "work_cutoff_monotonic_ns")), "creator-report-integer-context")
    core.digest(receipt["created_tree_commitment"])
    core.digest(receipt["extraction_receipt_sha256"])
    material = receipt["materialization"]
    need(material == {**selected["materialization"], "inventory_sha256": selected["inventory"]["sha256"],
                      "sdk_nar": inventory["nars"]["sdk"], "jdk_nar": inventory["nars"]["jdk"]}, "creator-materialization-output")
    qualification = receipt["carrier_qualification"]
    need(type(qualification) is dict and set(qualification) == {"outer_receipt_sha256", "report_sha256", "proof_inputs", "report"},
         "creator-carrier-qualified-record")
    core.digest(qualification["outer_receipt_sha256"])
    core.digest(qualification["report_sha256"])
    original_inputs = qualification["proof_inputs"]
    need(type(original_inputs) is dict and set(original_inputs) == {"repository", "mapping_sha256", "inputs"}
         and original_inputs["repository"] == "omux_native_sdk_carrier_proof_inputs"
         and type(original_inputs["inputs"]) is dict and set(original_inputs["inputs"]) == {
             "outer_receipt", "test_evidence", "test_log", "test_xml", "program_report"}, "creator-carrier-proof-record")
    core.digest(original_inputs["mapping_sha256"])
    for row in original_inputs["inputs"].values():
        need(type(row) is dict and set(row) == {"path", "sha256", "alias"}, "creator-carrier-proof-role")
        core.absolute(row["path"])
        core.relative(row["alias"])
        core.digest(row["sha256"])
    need(original_inputs["inputs"]["outer_receipt"]["sha256"] == qualification["outer_receipt_sha256"]
         and original_inputs["inputs"]["program_report"]["sha256"] == qualification["report_sha256"], "creator-carrier-proof-joins")
    need(core.sha(core.encoded(qualification["report"])) == qualification["report_sha256"], "creator-carrier-report-pin")
    need(qualification["report"]["carrier_receipt_sha256"] == inventory["carrier"]["receipt_sha256"]
         and qualification["report"]["origin_receipt_sha256"] == inventory["carrier"]["origin_receipt_sha256"],
         "creator-carrier-lineage")
    files = qualification["report"]["files"]
    need(type(files) is list and len(files) == 4, "creator-carrier-files")
    for row, expected_row in zip(files, recipe_doc["inputs"]["carrier"]):
        need(row == {"name": expected_row["name"], "sha256": expected_row["sha256"], "size": expected_row["bytes"]},
             "creator-recipe-carrier-tuple")
    lineage = inventory["carrier"]
    need({row["name"]: row["sha256"] for row in files} == {
        "receipt.json": lineage["receipt_sha256"], "manifest.json": lineage["manifest_sha256"],
        "payload.bin": lineage["payload_sha256"], "origin-receipt.json": lineage["origin_receipt_sha256"]},
        "inventory-exact-carrier-pins")
    marker = b"retained-sdk-tree: receipt-sha256=" + core.sha(held["program_receipt"].raw).encode("ascii")
    need(held["test_log"].raw.splitlines().count(marker) == 1, "creator-executed-program-marker")
    return core.encoded(origin)


def admit(runfiles, mapping_rows, entry_ns, until_ns, context, alias_owner):
    """Only closed declared public data and actual held selected success admit."""
    import codex_native_file_writer_model_source as family
    import codex_original_sdk_inputs as original
    import codex_retained_sdk_tree as proof_core
    need(type(alias_owner) is family.HeldControls, "current-held-controls")
    actual = original.validate_context(context)
    need(type(entry_ns) is int and type(until_ns) is int
         and int(actual["ENTRY_NS"]) == entry_ns and int(actual["DEADLINE_NS"]) == until_ns
         and until_ns - entry_ns == 1200 * 10**9 and entry_ns <= time.monotonic_ns() < entry_ns + 600 * 10**9,
         "current-original-source-envelope")
    cutoff = (entry_ns + 600 * 10**9) / 10**9
    need(family.source.DEADLINE == cutoff, "actual-current-source-admission")
    need(core.encoded(actual) == core.encoded({key: os.environ.get("OMUX_NATIVE_FILE_WRITER_MODELS_" + key)
                                             for key in original.CONTEXT_FIELDS}), "actual-source-environment")
    owner = AuthenticatedTreeInputs(_SEAL)
    owner.alias_owner, owner._owner_type = alias_owner, family.HeldControls
    owner._source = family.source
    owner.clock = core.Clock(cutoff)
    owner.clock.until_ns = owner.until_ns = entry_ns + 600 * 10**9
    owner.deadline = cutoff
    owner._context, owner._context_raw = tuple(original.CONTEXT_FIELDS), core.encoded(actual)
    owner._proof_core = proof_core
    try:
        alias_owner.fence()
        runfiles = core.absolute(runfiles)
        need(runfiles == Path(os.environ.get("TEST_SRCDIR", "")).resolve(strict=True), "actual-declared-runfiles")
        owner.runfiles = runfiles
        mapping_path = (runfiles / "_repo_mapping").resolve(strict=True)
        mapping = alias_owner.raws.get(str(mapping_path))
        need(type(mapping) is bytes and 0 < len(mapping) <= 1024 * 1024
             and any(row[0] == runfiles / "_repo_mapping" and row[1] == mapping_path for row in alias_owner.aliases)
             and [line.split(",") for line in mapping.decode().splitlines()] == mapping_rows,
             "actual-held-repository-mapping")
        # Config is a declared read-only control, not a caller-supplied path.
        control = owner._leaf(runfiles / CONFIG, MAX_SMALL, declaration=True)
        selected_raw = selection(control.raw)
        selected = core.decode(selected_raw)
        layout_leaf = owner._leaf(runfiles / DATA, MAX_SMALL)
        layout = _layout(layout_leaf.raw)
        held = _capture_proofs(owner, _mapped(runfiles, mapping_rows), selected)
        receipt = owner._leaf(runfiles / layout["artifact"]["receipt"], MAX_SMALL,
                              selected["receipt"]["sha256"], selected["receipt"]["bytes"])
        inventory = owner._leaf(runfiles / layout["artifact"]["inventory"], core.MAX_METADATA,
                                selected["inventory"]["sha256"], selected["inventory"]["bytes"])
        need(inventory.raw == held["selected_inventory"].raw, "declared-inventory-equals-original")
        recipe_leaf = owner._leaf(runfiles / layout["recipe"], core.MAX_METADATA,
                                  selected["materialization"]["recipe_sha256"])
        context_leaf = owner._leaf(runfiles / layout["creator_context"], MAX_SMALL)
        need(core.decode(context_leaf.raw) == selected["creator_context"]
             and context_leaf.raw == held["selected_creator_context"].raw
             and recipe_leaf.raw == held["selected_recipe"].raw, "declared-fixed-creator-context")
        logical, nars, lineage = proof_core.parse_inventory(inventory.raw, selected["inventory"]["sha256"], owner.clock)
        recipe_doc = recipe(recipe_leaf.raw, selected, owner.clock)
        report = core.decode(receipt.raw)
        origin = _qualify_creator(selected, held, report, core.decode(inventory.raw), recipe_doc)
        owner._inventory_raw, owner._receipt_raw = inventory.raw, receipt.raw
        owner._logical, owner._nars = logical, nars
        owner.tree_alias = runfiles / layout["artifact"]["root"]
        owner._tree_root = owner.tree_alias.resolve(strict=True)
        artifact_origin = core.decode(origin)
        prefix = str(Path(artifact_origin["output_base"]) / "execroot/_main/bazel-out") + "/"
        suffix = "/bin/tools/codex_native_retained_sdk_tree_materialized/sdk-tree-public/receipt.json"
        need(str(receipt.path).startswith(prefix) and str(receipt.path).endswith(suffix)
             and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", str(receipt.path)[len(prefix):-len(suffix)]) is not None,
             "actual-declared-action-output-namespace")
        need(owner._tree_root.name == "tree" and owner._tree_root.parent == receipt.path.parent == inventory.path.parent,
             "actual-declared-tree-products")
        owner.artifact_parent = _Directory(owner.tree_alias.parent.resolve(strict=True), owner.clock)
        before = os.stat(owner.tree_alias.name, dir_fd=owner.artifact_parent.fd, follow_symlinks=False)
        need(stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode), "declared-directory-alias-kind")
        owner.tree_alias_witness = core.identity(before)
        owner.tree_alias_literal = os.readlink(owner.tree_alias.name, dir_fd=owner.artifact_parent.fd) if stat.S_ISLNK(before.st_mode) else None
        extraction = owner._leaf(owner._tree_root / "extraction-receipt.json", MAX_SMALL, report["extraction_receipt_sha256"])
        extracted = core.decode(extraction.raw)
        need(type(extracted) is dict and set(extracted) == {"kind", "producer_context", "carrier_receipt_sha256",
             "origin_receipt_sha256", "manifest_sha256", "payload_sha256", "nars", "fresh_custody",
             "extracted_inventory_rechecked", "original_inodes_reused", "absolute_links_materialized_as_mounts",
             "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced"}
             and extracted["kind"] == core.EXTRACTED and extracted["carrier_receipt_sha256"] == core.decode(lineage)["receipt_sha256"]
             and extracted["manifest_sha256"] == core.decode(lineage)["manifest_sha256"]
             and extracted["payload_sha256"] == core.decode(lineage)["payload_sha256"]
             and extracted["origin_receipt_sha256"] == core.decode(lineage)["origin_receipt_sha256"]
             and core.encoded(extracted["nars"]) == nars
             and extracted["extracted_inventory_rechecked"] is True
             and all(extracted[k] is False for k in ("original_inodes_reused", "absolute_links_materialized_as_mounts",
                       "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced")), "durable-creator-extraction-provenance")
        custody = extracted["fresh_custody"]
        need(type(custody) is dict and set(custody) == {"sdk", "jdk"}, "creator-extraction-custody-roles")
        for row in custody.values():
            need(type(row) is dict and set(row) == {"root", "root_identity", "members_sha256"}
                 and type(row["root_identity"]) is list and len(row["root_identity"]) == 5
                 and all(type(value) is int for value in row["root_identity"]), "creator-extraction-custody-shape")
            core.absolute(row["root"])
            core.digest(row["members_sha256"])
        tree = _Directory(owner._tree_root, owner.clock)
        try:
            need(stat.S_IMODE(os.fstat(tree.fd).st_mode) == 0o555, "current-tree-top-sealed")
            core.names(tree.fd, {"sdk", "jdk", "extraction-receipt.json"}, owner.clock)
        finally: tree.close()
        for role in ("sdk", "jdk"):
            root = core.Root(owner._tree_root / role, owner.clock)
            try: owner._roots[role] = root
            except BaseException as error:
                try: root.close()
                except BaseException as cleanup: raise error from cleanup
                raise
        observed, actual_nars = proof_core.scan_retained_tree(owner._roots, logical, POLICY, owner.clock)
        need(actual_nars == nars, "first-current-complete-nars")
        owner._witnesses = MappingProxyType({key: tuple(row) for key, row in observed.items()})
        owner._qualification_raw = core.encoded({"selector_sha256": core.sha(control.raw), "selection": selected,
            "qualified_producer": {"outer_receipt_sha256": selected["producer"]["sha256"],
                "report_sha256": selected["receipt"]["sha256"], "artifact_origin": core.decode(origin)},
            "declaration": layout, "proof_inputs": {"kind": PROOF_KIND,
                "roles": {role: {"sha256": core.sha(leaf.raw), "bytes": len(leaf.raw)} for role, leaf in held.items()}}})
        owner.check()
        return owner
    except BaseException as error:
        try: owner.close()
        except BaseException as cleanup: raise error from cleanup
        raise


class CreatorCarrierInputs:
    """Creator's actual original seal evidence owner; not full carrier bytes."""
    def __init__(self, seal):
        need(seal is _SEAL, "private-creator-constructor")
        self.scope = self.controls = None
        self.carrier = None
        self.carrier_open_consumed = False
        self.active, self.finished = True, False
        self.pid, self.thread = os.getpid(), threading.get_ident()

    @property
    def root(self): return self._root
    @property
    def pin(self): return self._pin
    @property
    def qualified(self):
        self.check()
        return core.decode(self._qualified_raw)
    @property
    def selection(self):
        self.check()
        return core.decode(self._selection_raw)

    def proof_metadata(self):
        """Exact already-held evidence bytes; no general private-file reader."""
        self.check()
        return self._proof_metadata

    def open_carrier(self):
        """One actual full-byte owner on the SAME original creator Clock."""
        self.check()
        need(not self.carrier_open_consumed, "creator-single-carrier-owner")
        self.carrier_open_consumed = True
        need(type(self) in (CreatorCarrierInputs, PublicCreatorCarrierInputs), "creator-exact-owner-type")
        held = (core.PublicHeldCarrier(self._root, self._pin, self.deadline, self.sdk_domain)
            if type(self) is PublicCreatorCarrierInputs else core.HeldCarrier(self._root, self._pin, self.deadline))
        # No descriptors/proof exist before this exact Clock join. The helper
        # owns the pending object before returning its context to the writer.
        held._clock = self.clock
        held._deadline, held._until_ns = self.deadline, self.until_ns
        self.carrier = held
        return held

    def check(self):
        need(self.active and self.scope is not None and self.controls is not None
             and os.getpid() == self.pid and threading.get_ident() == self.thread
             and self.clock.deadline == self.deadline and self.clock.until_ns == self.until_ns,
             "creator-current-owner")
        self.clock.tick()
        need(core.encoded({key: os.environ.get("OMUX_NATIVE_SDK_TREE_" + key) for key in self.context}) == self.context_raw,
             "creator-current-environment")
        current_creator_domain(self.current_domain_raw, core.decode(self.context_raw))
        self.controls.fence()
        self._metadata.recheck_aliases(self.aliases, self.deadline)
        self.proofs.recheck(self.deadline)
        self.clock.tick()

    def full(self):
        self.check()
        self.controls.full()
        self.check()

    def finish(self):
        need(not self.finished, "creator-one-final")
        carrier_type = core.PublicHeldCarrier if type(self) is PublicCreatorCarrierInputs else core.HeldCarrier
        need(type(self.carrier) is carrier_type and self.carrier._clock is self.clock
             and self.carrier._active and self.carrier._final and self.carrier._final_fresh
             and self.carrier._extracted is not None, "creator-complete-held-carrier-and-final-fresh")
        self.carrier.check()
        self.full()
        self.carrier.check()
        self.finished = True

    def close(self):
        self.active = False
        controls, self.controls = self.controls, None
        scope, self.scope = self.scope, None
        carrier, self.carrier = self.carrier, None
        first = None
        if carrier is not None:
            try: carrier.close()
            except BaseException as error: first = error
        if controls is not None:
            try: controls.close()
            except BaseException as error:
                if first is None: first = error
        if scope is not None:
            try: scope.__exit__(None, None, None)
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, exc_type, error, trace):
        try:
            if exc_type is None:
                need(self.finished, "creator-success-requires-final")
                self.check()
        except BaseException as refusal:
            try: self.close()
            except BaseException as cleanup: raise refusal from cleanup
            raise
        try: self.close()
        except BaseException as cleanup:
            if error is not None:
                prior = BaseException.__cause__.__get__(error)
                raise BaseException.with_traceback(error, trace) from (cleanup if prior is None else prior)
            raise
        if exc_type is None: self.clock.tick()

    def __copy__(self): raise ValueError("creator-inputs-not-transferable")
    def __deepcopy__(self, unused): raise ValueError("creator-inputs-not-transferable")
    def __reduce_ex__(self, unused): raise ValueError("creator-inputs-not-transferable")


class PublicCreatorCarrierInputs(CreatorCarrierInputs):
    """Exact public-SDK creator owner; never accepted as a default private owner."""
    def __init__(self, seal, domain):
        import codex_public_sdk_custody as public
        need(type(self) is PublicCreatorCarrierInputs and type(domain) is public.Domain,
             "public-creator-exact-domain")
        super().__init__(seal)
        self.sdk_domain = domain

    def check(self):
        self.sdk_domain.check()
        need(self.clock is self.sdk_domain.clock, "public-creator-same-clock")
        super().check()
        self.sdk_domain.check()

    def __exit__(self, exc_type, error, trace):
        try:
            if exc_type is None:
                need(self.finished, "creator-success-requires-final")
                self.check()
        except BaseException as refusal:
            try: self.close()
            except BaseException as cleanup: raise refusal from core._first_cause(refusal, cleanup)
            raise
        try: self.close()
        except BaseException as cleanup:
            if error is not None:
                raise BaseException.with_traceback(error, trace) from core._first_cause(error, cleanup)
            raise
        if exc_type is None: self.clock.tick()


def admit_carrier(runfiles, mapping_rows, creator_context, current_domain_raw, *, sdk_domain=None):
    """Genuine original five-role evidence; creator still proves full bytes."""
    import codex_native_carrier_metadata as metadata
    import codex_native_file_writer_model_source as family
    entry, until = _context(creator_context)
    current_creator_domain(current_domain_raw, creator_context)
    need(core.encoded(creator_context) == core.encoded({key: os.environ.get("OMUX_NATIVE_SDK_TREE_" + key)
                                                      for key in creator_context}), "actual-creator-environment")
    need(entry <= time.monotonic_ns() < entry + 1170 * 10**9, "actual-creator-original-work")
    if sdk_domain is not None:
        import codex_public_sdk_custody as public
        need(type(sdk_domain) is public.Domain and sdk_domain.context == core.encoded(creator_context),
             "public-admission-same-context")
        sdk_domain.confirm(current_domain_raw)
    owner = CreatorCarrierInputs(_SEAL) if sdk_domain is None else PublicCreatorCarrierInputs(_SEAL, sdk_domain)
    owner.clock = core.Clock((entry + 1170 * 10**9) / 10**9) if sdk_domain is None else sdk_domain.clock
    owner.clock.until_ns = owner.until_ns = entry + 1170 * 10**9
    owner.deadline = owner.clock.deadline
    owner.context, owner.context_raw = tuple(creator_context), core.encoded(creator_context)
    owner.current_domain_raw = current_domain_raw
    owner._metadata = metadata
    try:
        owner.scope = metadata.proof_scope(owner.deadline) if sdk_domain is None else metadata.proof_scope(
            owner.deadline, sdk_domain=sdk_domain)
        owner.scope.__enter__()
        owner.controls = family.HeldControls() if sdk_domain is None else public.Controls(sdk_domain)
        # proof_scope's initial configure read is provisional. Retain both
        # fixed declared ancestry controls before selected/config qualification;
        # they remain held through actual full final proof and recipe emission.
        control_root = metadata.binding.ninth.parent.ROOT
        owner.controls.add(control_root / metadata.binding.CONFIG, maximum=16384)
        owner.controls.add(control_root / metadata.binding.N9_WITNESS,
            metadata.binding.N9_WITNESS_SHA, 16384)
        config_path = control_root / metadata.CONFIG
        config_raw = owner.controls.add(config_path, maximum=16384)
        selected = metadata.selection(config_raw) if sdk_domain is None else metadata.selection(config_raw, sdk_domain=sdk_domain)
        root, aliases, declaration = (metadata.declared_carrier(Path(runfiles), mapping_rows, selected, owner.deadline)
            if sdk_domain is None else metadata.declared_carrier(Path(runfiles), mapping_rows, selected, owner.deadline,
                sdk_domain=sdk_domain))
        for alias, physical in aliases: owner.controls.add_alias(alias, physical)
        # The repository exports a fifth declared control alongside four blobs.
        # Retain its actual selected bytes before recipe emission can use them;
        # an alias witness alone is not a bounded authenticated proof input.
        declaration_aliases = [alias for alias, physical in aliases
            if str(physical) == declaration["selection_path"]]
        need(len(declaration_aliases) == 1, "creator-exact-carrier-declaration-alias")
        owner.controls.add(declaration_aliases[0], declaration["selection_sha256"], 8192)
        proofs = (metadata.declared_proofs(Path(runfiles), mapping_rows, selected, owner.deadline)
            if sdk_domain is None else metadata.declared_proofs(Path(runfiles), mapping_rows, selected, owner.deadline,
                sdk_domain=sdk_domain))
        mapping_aliases = [alias for alias, physical in proofs.aliases if physical == proofs.path]
        need(len(mapping_aliases) == 1, "creator-proof-mapping-alias")
        owner.controls.add(mapping_aliases[0], proofs.sha256, MAX_SMALL)
        captured = owner.controls.carrier_proofs(selected, proofs, owner.deadline)
        class Captured:
            pass
        held = {}
        for role in ("test_log", "test_xml"):
            view = Captured()
            view.path = Path(proofs.document["proofs"][role]["path"])
            view.raw = captured[role]
            held[role] = view
        _collector(core.decode(captured["test_evidence"]), core.decode(captured["outer_receipt"]),
                   {"producer": selected["qualification"]["producer"]}, held, metadata.SEAL_TARGET)
        qualified = metadata.qualify_producer(selected, owner.deadline, proofs)
        # The real executed seal program emits exactly one canonical report line.
        expected = core.encoded(qualified["report"])
        lines = []
        for line in captured["test_log"].splitlines():
            owner.clock.tick()
            if not line.startswith(b"{"): continue
            try: document = core.decode(line)
            except (ValueError, UnicodeError): continue
            if type(document) is dict and document.get("kind") == metadata.PRODUCER_KIND: lines.append(line)
        need(lines == [expected], "creator-original-executed-seal-marker")
        need(qualified["report"]["carrier_receipt_sha256"] == selected["carrier"]["receipt_sha256"]
             and declaration["selection"]["digests"] == {row["name"]: row["sha256"] for row in qualified["report"]["files"]},
             "creator-original-carrier-declaration")
        owner._root, owner._pin = root, selected["carrier"]["receipt_sha256"]
        if sdk_domain is not None: sdk_domain.bind_carrier(root, owner._pin)
        owner.aliases, owner.proofs = aliases, proofs
        owner._selection_raw, owner._qualified_raw = core.encoded(selected), core.encoded(qualified)
        owner._proof_metadata = MappingProxyType({path: MappingProxyType({"raw": raw,
            "sha256": core.sha(raw), "bytes": len(raw)}) for path, raw in owner.controls.raws.items()})
        owner.full()
        return owner
    except BaseException as error:
        try: owner.close()
        except BaseException as cleanup:
            if sdk_domain is not None: raise error from core._first_cause(error, cleanup)
            raise error from cleanup
        raise
