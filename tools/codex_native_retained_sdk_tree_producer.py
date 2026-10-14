"""Create one declared public SDK tree, then independently qualify retained bytes.

Mutable private proposal. No output or marker establishes genuine success until
its actual guarded producer receipt/XML/physical retention are admitted. Cold
replay keeps the pinned creator clock and fails once that clock has expired.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat

import codex_native_sdk_carrier as core
import codex_original_sdk_inputs as original
import codex_retained_sdk_tree as tree
import codex_retained_sdk_tree_inputs as admission

OUTPUTS = list(admission.OUTPUTS)
ACTION_KIND = "omux-retained-public-sdk-tree-declared-action-inputs-v1"


class PublicInput:
    """Declared code/tool bytes; this scope grants no SDK input authority."""
    def __init__(self, path, clock):
        self.alias, self.clock = core.absolute(path), clock
        self.parent = self.alias_parent = self.fd = None
        self.closed = False
        try:
            self.path = self.alias.resolve(strict=True)
            self.alias_parent = admission._Directory(self.alias.parent.resolve(strict=True), clock)
            self.alias_witness = core.identity(os.stat(self.alias.name, dir_fd=self.alias_parent.fd, follow_symlinks=False))
            core.need(stat.S_ISREG(self.alias_witness[4]) or stat.S_ISLNK(self.alias_witness[4]), "sdk-tree-public-alias-kind")
            self.alias_literal = os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) if stat.S_ISLNK(self.alias_witness[4]) else None
            self.parent = admission._Directory(self.path.parent, clock)
            before = os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)
            core.need(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid())
                and stat.S_IMODE(before.st_mode) in (0o444, 0o555, 0o644, 0o755)
                and 0 <= before.st_size <= core.MAX_METADATA,
                "sdk-tree-declared-public-input")
            self.witness = core.identity(before)
            self.fd = os.open(self.path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=self.parent.fd)
            self.check()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: raise error from cleanup
            raise

    def check(self):
        self.clock.tick()
        core.need(not self.closed and self.fd is not None and self.alias.resolve(strict=True) == self.path,
                  "sdk-tree-public-input-current-alias")
        self.parent.check(); self.alias_parent.check()
        core.need(self.alias.parent.resolve(strict=True) == self.alias_parent.path
            and core.identity(os.stat(self.alias.name, dir_fd=self.alias_parent.fd, follow_symlinks=False)) == self.alias_witness
            and (self.alias_literal is None or os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) == self.alias_literal),
            "sdk-tree-public-input-alias-witness")
        core.need(core.identity(os.fstat(self.fd)) == self.witness == core.identity(
            os.stat(self.path.name, dir_fd=self.parent.fd, follow_symlinks=False)),
            "sdk-tree-public-input-held-name")

    def digest(self):
        self.check()
        os.lseek(self.fd, 0, os.SEEK_SET)
        count, digest = 0, hashlib.sha256()
        while True:
            self.clock.tick()
            block = os.read(self.fd, 65536)
            self.clock.tick()
            if not block: break
            count += len(block)
            core.need(count <= self.witness[6], "sdk-tree-public-input-size")
            digest.update(block)
        core.need(count == self.witness[6], "sdk-tree-public-input-complete")
        self.check()
        return digest.hexdigest(), count

    def close(self):
        self.closed = True
        fd = self.fd; self.fd = None
        parent = self.parent; self.parent = None
        alias_parent = self.alias_parent; self.alias_parent = None
        first = None
        if fd is not None:
            try: os.close(fd)
            except BaseException as error: first = error
        if parent is not None:
            try: parent.close()
            except BaseException as error:
                if first is None: first = error
        if alias_parent is not None:
            try: alias_parent.close()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first

    def __enter__(self): return self
    def __exit__(self, kind, error, trace):
        try: self.close()
        except BaseException as cleanup:
            if error is not None: raise BaseException.with_traceback(error, trace) from cleanup
            raise
        return False


def _execution_path(path):
    core.need(type(path) is str and path and "\x00" not in path, "sdk-tree-execution-path")
    selected = Path(path)
    if not selected.is_absolute(): selected = Path.cwd() / selected
    return core.absolute(selected)


def _descriptor(raw, clock):
    clock.tick()
    doc = core.decode(raw)
    core.need(type(doc) is dict and set(doc) == {"schema_version", "kind", "code", "tools", "proofs", "carrier"}
        and type(doc["schema_version"]) is int and doc["schema_version"] == 1
        and doc["kind"] == ACTION_KIND, "sdk-tree-action-descriptor")
    core.need(type(doc["code"]) is list and 0 < len(doc["code"]) <= 4096
        and type(doc["tools"]) is list and 0 < len(doc["tools"])
        and len(doc["code"]) + len(doc["tools"]) <= core.MAX_ENTRIES,
        "sdk-tree-action-code-tool-bound")
    core.need(type(doc["proofs"]) is list and 0 < len(doc["proofs"]) <= 64
        and len(doc["code"]) + len(doc["tools"]) + len(doc["proofs"]) <= core.MAX_ENTRIES,
        "sdk-tree-proof-input-bound")
    seen = set()
    for role in ("code", "tools", "proofs"):
        for row in doc[role]:
            clock.tick()
            core.need(type(row) is dict and set(row) == {"logical_path", "execution_path"},
                      "sdk-tree-declared-member")
            core.relative(row["logical_path"])
            path = _execution_path(row["execution_path"])
            core.need(row["logical_path"] not in seen, "sdk-tree-declared-member-duplicate")
            seen.add(row["logical_path"])
    core.need(type(doc["carrier"]) is list and len(doc["carrier"]) == 4
        and [row.get("name") for row in doc["carrier"]] == list(core.FILES), "sdk-tree-action-four-carrier")
    for row in doc["carrier"]:
        core.need(type(row) is dict and set(row) == {"name", "logical_path", "execution_path"}, "sdk-tree-carrier-row")
        core.relative(row["logical_path"])
        core.need(row["logical_path"] not in seen, "sdk-tree-carrier-logical-collision")
        seen.add(row["logical_path"])
        _execution_path(row["execution_path"])
    clock.tick()
    return doc


def _read_small(path, clock, maximum=65536):
    with PublicInput(path, clock) as owner:
        core.need(0 < owner.witness[6] <= maximum, "sdk-tree-control-size")
        raw = bytearray()
        while True:
            clock.tick()
            block = os.read(owner.fd, min(65536, maximum))
            clock.tick()
            if not block: break
            core.need(len(raw) + len(block) <= maximum, "sdk-tree-control-bound")
            raw.extend(block)
        owner.check()
        core.need(len(raw) == owner.witness[6], "sdk-tree-control-complete")
        return bytes(raw)


def _recipe(descriptor, creator):
    clock = creator.clock
    inputs, witnesses = {"code": [], "tools": [], "proofs": [], "carrier": []}, {}
    for role in ("code", "tools"):
        for row in sorted(descriptor[role], key=lambda row: row["logical_path"]):
            clock.tick()
            with PublicInput(_execution_path(row["execution_path"]), clock) as held:
                pin, count = held.digest()
                witnesses[(role, row["logical_path"])] = (str(held.path), held.witness)
            inputs[role].append({"path": row["logical_path"], "sha256": pin, "bytes": count})
    proof_metadata = creator.proof_metadata()
    for row in sorted(descriptor["proofs"], key=lambda row: row["logical_path"]):
        clock.tick()
        physical = str(_execution_path(row["execution_path"]).resolve(strict=True))
        core.need(physical in proof_metadata, "sdk-tree-admitted-proof-path")
        selected = proof_metadata[physical]
        core.need(core.sha(selected["raw"]) == selected["sha256"] and len(selected["raw"]) == selected["bytes"],
                  "sdk-tree-admitted-proof-bytes")
        inputs["proofs"].append({"path": row["logical_path"], "sha256": selected["sha256"], "bytes": selected["bytes"]})
    files = creator.qualified["report"]["files"]
    for row, selected in zip(descriptor["carrier"], files):
        clock.tick()
        core.need(_execution_path(row["execution_path"]).resolve(strict=True) == creator.root / row["name"]
            and row["name"] == selected["name"], "sdk-tree-current-declared-carrier")
        inputs["carrier"].append({"name": row["name"], "sha256": selected["sha256"], "bytes": selected["size"]})
    raw = core.encoded({"schema_version": 1, "kind": admission.RECIPE_KIND,
        "producer": tree.TARGET, "profile": tree.PROFILE, "inputs": inputs,
        "outputs": OUTPUTS, "physical_mode_policy": tree.PHYSICAL_POLICY})
    clock.tick()
    return raw, witnesses


def _recheck_recipe(descriptor, raw, witnesses, clock):
    expected = core.decode(raw)["inputs"]
    for role in ("code", "tools"):
        rows = sorted(descriptor[role], key=lambda row: row["logical_path"])
        for row, selected in zip(rows, expected[role]):
            clock.tick()
            with PublicInput(_execution_path(row["execution_path"]), clock) as held:
                core.need((str(held.path), held.witness) == witnesses[(role, row["logical_path"])],
                          "sdk-tree-original-declared-input-witness")
                core.need(held.digest() == (selected["sha256"], selected["bytes"]), "sdk-tree-final-declared-input")
    clock.tick()


def _write_leaf(parent, name, raw, clock):
    clock.tick(); parent.check()
    fd = None
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600, dir_fd=parent.fd)
        core.write_all(fd, raw, clock)
        os.fchmod(fd, 0o444); os.fsync(fd)
        witness = core.identity(os.fstat(fd))
        core.need(witness == core.identity(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)),
                  "sdk-tree-created-metadata-name")
    except BaseException as error:
        held, fd = fd, None
        if held is not None:
            try: os.close(held)
            except BaseException as cleanup: raise error from cleanup
        raise
    else:
        held, fd = fd, None
        os.close(held)
    os.fsync(parent.fd); parent.check(); clock.tick()
    return witness


def _drain(resources, error=None):
    first = None
    for resource in resources:
        if resource is None: continue
        try: resource.close()
        except BaseException as cleanup:
            if first is None: first = cleanup
    if first is not None:
        if error is not None:
            prior = BaseException.__cause__.__get__(error)
            raise error from (first if prior is None else prior)
        raise first


def _relocate_owned_tree(stage, parent, tree_fd, expected, clock):
    """Move only the same owned top directory; descendants stay sealed."""
    stage.check(); parent.check(); clock.tick()
    held = os.fstat(tree_fd)
    core.need(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid()
        and stat.S_IMODE(held.st_mode) == 0o555
        and core.identity(held, True) == expected == core.identity(
            os.stat("tree", dir_fd=stage.fd, follow_symlinks=False), True),
        "sdk-tree-owned-sealed-relocation-root")
    owner = expected[:4]
    changed_mode = False
    try:
        # Linux must update '..' on cross-parent directory rename. Permission
        # applies only to this held owned root inside the private stage.
        changed_mode = True
        os.fchmod(tree_fd, 0o700)
        writable = core.identity(os.fstat(tree_fd), True)
        core.need(writable[:4] == owner and stat.S_ISDIR(writable[4])
            and stat.S_IMODE(writable[4]) == 0o700
            and writable == core.identity(os.stat("tree", dir_fd=stage.fd,
                follow_symlinks=False), True), "sdk-tree-private-writable-held-root")
        stage.check(); parent.check(); clock.tick()
        try: os.stat("tree", dir_fd=parent.fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError("SDK carrier refused: sdk-tree-relocation-output-already-exists")
        clock.tick()
        os.rename("tree", "tree", src_dir_fd=stage.fd, dst_dir_fd=parent.fd)
        core.need(writable == core.identity(os.fstat(tree_fd), True) == core.identity(
            os.stat("tree", dir_fd=parent.fd, follow_symlinks=False), True),
            "sdk-tree-moved-writable-held-root")
        # Reseal before opening any published Root or fresh namespace reader.
        os.fchmod(tree_fd, 0o555)
        core.need(expected == core.identity(os.fstat(tree_fd), True) == core.identity(
            os.stat("tree", dir_fd=parent.fd, follow_symlinks=False), True),
            "sdk-tree-moved-resealed-held-root")
        os.fsync(tree_fd); os.fsync(stage.fd); os.fsync(parent.fd)
        stage.check(); parent.check(); clock.tick()
        return expected
    except BaseException as error:
        if changed_mode:
            try:
                # This is mandatory permission-tightening cleanup, not proof
                # or a renewed clock. The original held FD still owns it.
                held = os.fstat(tree_fd)
                core.need(stat.S_ISDIR(held.st_mode) and held.st_uid == os.getuid()
                    and core.identity(held, True)[:4] == owner,
                    "sdk-tree-cleanup-same-owned-root")
                os.fchmod(tree_fd, 0o555)
                os.fsync(tree_fd)
            except BaseException as cleanup:
                prior = BaseException.__cause__.__get__(error)
                raise error from (cleanup if prior is None else prior)
        raise


def materialize(args):
    fields = ("MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256")
    context = {name: os.environ.get("OMUX_NATIVE_SDK_TREE_" + name) for name in fields}
    entry, until = admission._context(context)
    clock = core.Clock((entry + 1170 * 10**9) / 10**9)
    clock.until_ns = entry + 1170 * 10**9
    core.need(0 < entry <= core.time.monotonic_ns() < clock.until_ns, "sdk-tree-original-creator-clock")
    context_path = _execution_path(args.creator_context)
    context_raw = _read_small(context_path, clock)
    core.need(core.decode(context_raw) == context, "sdk-tree-actual-pinned-creator-context")
    runfiles = Path(os.environ["RUNFILES_DIR"]).resolve(strict=True)
    mapping = _read_small(runfiles / "_repo_mapping", clock, 1024 * 1024)
    rows = [row.split(",") for row in mapping.decode().splitlines()]
    core.need(all(len(row) == 3 for row in rows), "sdk-tree-creator-repository-mapping")
    creator = parent = stage = carrier = published = None
    old_roots, new_roots = {"sdk": None, "jdk": None}, {"sdk": None, "jdk": None}
    old_tree_fd = None
    try:
        creator = admission.admit_carrier(runfiles, rows, context)
        core.need(type(creator) is admission.CreatorCarrierInputs, "sdk-tree-real-carrier-creator-owner")
        clock = creator.clock
        core.need(clock.until_ns == entry + 1170 * 10**9 and clock.deadline == clock.until_ns / 10**9,
                  "sdk-tree-same-original-creator-clock")
        descriptor_path = _execution_path(args.input_descriptor)
        descriptor_raw = _read_small(descriptor_path, clock, core.MAX_METADATA)
        descriptor = _descriptor(descriptor_raw, clock)
        tree_path = _execution_path(args.tree_output)
        paths = [_execution_path(value) for value in (args.inventory_output, args.receipt_output, args.recipe_output)]
        parent_path = tree_path.parent
        core.need(tree_path.name == "tree" and parent_path.name == "sdk-tree-public"
            and parent_path.parent.name == "codex_native_retained_sdk_tree_materialized"
            and [path.name for path in paths] == ["inventory.json", "receipt.json", "recipe.json"]
            and all(path.parent == parent_path for path in paths) and context_path.parent == parent_path
            and context_path.name == "creator-context.json" and descriptor_path.parent == parent_path
            and descriptor_path.name == "declared-inputs.json", "sdk-tree-exact-action-output-roles")
        recipe_raw, input_witnesses = _recipe(descriptor, creator)
        parent = admission._Directory(parent_path, clock)
        for name in ("tree", "inventory.json", "receipt.json", "recipe.json", ".sdk-tree-creation-private"):
            try: os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise ValueError("SDK carrier refused: sdk-tree-output-already-exists")
        parent.check(); clock.tick()
        os.mkdir(".sdk-tree-creation-private", mode=0o700, dir_fd=parent.fd)
        stage_path = parent_path / ".sdk-tree-creation-private"
        stage = core.Root(stage_path, clock, sealed=False, owned=True)
        core.need(os.fstat(stage.fd).st_dev == os.fstat(parent.fd).st_dev,
                  "sdk-tree-single-filesystem-publication")
        carrier = creator.open_carrier()
        carrier.__enter__()
        report, manifest, logical, unused_files = carrier._binding()
        core.need(report["origin"]["receipt_sha256"] == original.ORIGIN_PIN,
                  "sdk-tree-fixed-original-recipe")
        creator.check()
        extraction = core.extract(creator.root, creator.pin, stage_path / "tree", clock.deadline,
            _held_carrier=carrier)
        # Preserve the default writer's durability and final full carrier proof.
        carrier.full_final()
        core.need(core.revalidate_extraction(creator.root, creator.pin, stage_path / "tree", clock.deadline,
            pinned_extraction_receipt_sha256=core.sha(core.encoded(extraction)), _held_carrier=carrier) == extraction,
            "sdk-tree-complete-created-final-proof")
        for role in ("sdk", "jdk"):
            old_roots[role] = core.Root(stage_path / "tree" / role, clock)
        before = core._fresh_namespace(old_roots, logical, clock)
        for role in ("sdk", "jdk"):
            selected = extraction["fresh_custody"][role]
            core.need(core.sha(core.encoded([[name, witness] for (which, name), witness in sorted(before.items())
                if which == role])) == selected["members_sha256"], "sdk-tree-created-member-identity")
        _drain(tuple(old_roots.values()))
        for role in ("sdk", "jdk"): old_roots[role] = None
        old_tree_fd = os.open("tree", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage.fd)
        old_tree = core.identity(os.fstat(old_tree_fd), True)
        core.need(old_tree == core.identity(os.stat("tree", dir_fd=stage.fd, follow_symlinks=False), True),
                  "sdk-tree-held-created-root")
        core.need(_relocate_owned_tree(stage, parent, old_tree_fd, old_tree, clock) == old_tree,
                  "sdk-tree-relocation-same-sealed-owner")
        core.need(old_tree == core.identity(os.fstat(old_tree_fd), True) == core.identity(
            os.stat("tree", dir_fd=parent.fd, follow_symlinks=False), True), "sdk-tree-owned-rename-root")
        published = core.Root(tree_path, clock)
        core.need(core.identity(os.fstat(published.fd)) == core.identity(os.fstat(old_tree_fd)),
                  "sdk-tree-published-held-root")
        core.names(published.fd, {"sdk", "jdk", "extraction-receipt.json"}, clock)
        for role in ("sdk", "jdk"):
            new_roots[role] = core.Root(tree_path / role, clock)
        observed, after, nars = core._scan_nar(new_roots, logical, clock)
        core.need(observed == logical and after == before and nars == manifest["nars"],
                  "sdk-tree-published-complete-original-proof")
        core.need(core.read(published, "extraction-receipt.json", 65536,
            core.sha(core.encoded(extraction))) == core.encoded(extraction), "sdk-tree-created-extraction-receipt")
        inventory_raw = tree.inventory_document(creator.pin, report, nars, logical, clock)
        _recheck_recipe(descriptor, recipe_raw, input_witnesses, clock)
        creator.finish()
        carrier.check(); published.check(); parent.check()
        core.need(core._fresh_namespace(new_roots, logical, clock) == before,
                  "sdk-tree-final-all-member-physical-fence")
        program = {"schema_version": 1, "kind": tree.REPORT_KIND, "producer": tree.TARGET,
            "producer_context": {"mode": tree.PROFILE, "epoch": context["EPOCH"],
                "source_commit": context["SOURCE_COMMIT"], "graph_sha256": context["GRAPH_SHA256"],
                "entry_monotonic_ns": entry, "deadline_monotonic_ns": until, "work_cutoff_monotonic_ns": clock.until_ns},
            "inventory": {"sha256": core.sha(inventory_raw), "bytes": len(inventory_raw)},
            "tree_root": "tree", "extraction_receipt_sha256": core.sha(core.encoded(extraction)),
            "physical_mode_policy": tree.PHYSICAL_POLICY, "created_tree_commitment": core.sha(core.encoded(
                [[role, name, witness] for (role, name), witness in sorted(after.items())])),
            "carrier_qualification": creator.qualified,
            "materialization": {"recipe_sha256": core.sha(recipe_raw),
                "action_inputs_sha256": core.sha(core.encoded(core.decode(recipe_raw)["inputs"])),
                "inventory_sha256": core.sha(inventory_raw), "sdk_nar": nars["sdk"], "jdk_nar": nars["jdk"]},
            "sdk_execution_qualified": False, "source_qualified": False, "compiler_qualified": False,
            "runtime_qualified": False}
        program_raw = core.encoded(program)
        created = {}
        for name, raw in (("recipe.json", recipe_raw), ("inventory.json", inventory_raw), ("receipt.json", program_raw)):
            created[name] = _write_leaf(parent, name, raw, clock)
        for name, raw in (("recipe.json", recipe_raw), ("inventory.json", inventory_raw), ("receipt.json", program_raw)):
            core.need(_read_small(parent_path / name, clock, core.MAX_METADATA) == raw
                and core.identity(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)) == created[name],
                "sdk-tree-published-control-readback")
        stage.check(); stage.close(); stage = None
        os.rmdir(".sdk-tree-creation-private", dir_fd=parent.fd)
        os.fsync(parent.fd)
        creator.full(); carrier.check()
        core.need(_read_small(context_path, clock) == context_raw
            and _read_small(descriptor_path, clock, core.MAX_METADATA) == descriptor_raw,
            "sdk-tree-action-controls-final")
        core.need(core._fresh_namespace(new_roots, logical, clock) == before,
                  "sdk-tree-after-publication-all-member-fence")
        _fence_recipe(descriptor, input_witnesses, clock)
        creator.check(); carrier.check(); published.check(); parent.check(); clock.tick()
    except BaseException as error:
        try:
            if old_tree_fd is not None: os.close(old_tree_fd)
        except BaseException as cleanup: raise error from cleanup
        finally:
            _drain(tuple(old_roots.values()) + tuple(new_roots.values()) + (published, stage, parent, carrier, creator), error)
        raise
    else:
        first = None
        if old_tree_fd is not None:
            try: os.close(old_tree_fd)
            except BaseException as error: first = error
        # Enforce final proof while attempting every other owner even when
        # normal close itself fails. Never retry a possibly reused raw FD.
        if carrier is not None:
            try: carrier.__exit__(None, None, None)
            except BaseException as error:
                if first is None: first = error
        _drain(tuple(new_roots.values()) + (published, parent, creator), first)
        if first is not None: raise first
        clock.tick()


def _capture_public(owner, maximum):
    owner.check()
    core.need(0 < owner.witness[6] <= maximum, "sdk-tree-captured-control-size")
    os.lseek(owner.fd, 0, os.SEEK_SET)
    raw = bytearray()
    while True:
        owner.clock.tick()
        block = os.read(owner.fd, min(65536, maximum))
        owner.clock.tick()
        if not block: break
        core.need(len(raw) + len(block) <= maximum, "sdk-tree-captured-control-bound")
        raw.extend(block)
    owner.check()
    core.need(len(raw) == owner.witness[6], "sdk-tree-captured-control-complete")
    return bytes(raw)


def _runfiles_descriptor(descriptor, runfiles):
    # Execution paths are action-local. Qualification uses the SAME declared
    # logical members in its actual runfiles; path spelling is not identity.
    result = {"schema_version": 1, "kind": ACTION_KIND}
    for role in ("code", "tools", "proofs"):
        result[role] = [{"logical_path": row["logical_path"],
            "execution_path": str(runfiles / row["logical_path"])}
            for row in descriptor[role]]
    result["carrier"] = [{"name": row["name"], "execution_path": str(runfiles / row["logical_path"])}
        for row in descriptor["carrier"]]
    return result


def _fence_recipe(descriptor, witnesses, clock):
    for role in ("code", "tools"):
        for row in descriptor[role]:
            with PublicInput(_execution_path(row["execution_path"]), clock) as held:
                core.need((str(held.path), held.witness) == witnesses[(role, row["logical_path"])],
                          "sdk-tree-final-declared-input-physical-fence")
    clock.tick()


class _TreeScan:
    """Current physical byte/semantic proof only; no producer success token."""
    def __init__(self, path, logical, clock):
        self.alias, self.expected, self.clock = core.absolute(path), logical, clock
        self.path = self.alias.resolve(strict=True)
        self.alias_parent = None
        self.root = None
        self.roots = {"sdk": None, "jdk": None}
        try:
            self.alias_parent = admission._Directory(self.alias.parent.resolve(strict=True), clock)
            before = os.stat(self.alias.name, dir_fd=self.alias_parent.fd, follow_symlinks=False)
            core.need(stat.S_ISDIR(before.st_mode) or stat.S_ISLNK(before.st_mode), "sdk-tree-qualifier-directory-alias-kind")
            self.alias_witness = core.identity(before)
            self.alias_literal = os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) if stat.S_ISLNK(before.st_mode) else None
            self.root = core.Root(self.path, clock)
            core.names(self.root.fd, {"sdk", "jdk", "extraction-receipt.json"}, clock)
            for role in self.roots: self.roots[role] = core.Root(self.path / role, clock)
            self.witnesses, self.nars = tree.scan_retained_tree(self.roots, logical, tree.PHYSICAL_POLICY, clock)
            self.check()
        except BaseException as error:
            _drain(tuple(self.roots.values()) + (self.root, self.alias_parent), error)
            raise

    def check(self):
        self.clock.tick(); self.root.check(); self.alias_parent.check()
        core.need(self.alias.resolve(strict=True) == self.path and self.alias.parent.resolve(strict=True) == self.alias_parent.path
            and core.identity(os.stat(self.alias.name, dir_fd=self.alias_parent.fd, follow_symlinks=False)) == self.alias_witness
            and (self.alias_literal is None or os.readlink(self.alias.name, dir_fd=self.alias_parent.fd) == self.alias_literal),
            "sdk-tree-qualifier-current-directory-alias")
        core.names(self.root.fd, {"sdk", "jdk", "extraction-receipt.json"}, self.clock)
        for root in self.roots.values(): root.check()
        self.clock.tick()

    def read_regular(self, role, name, maximum):
        self.check()
        row = self.expected.get((role, name))
        core.need(row is not None and row["kind"] == "file" and row["size"] <= maximum,
                  "sdk-tree-semantic-declared-regular")
        raw = core.read(self.roots[role], name, maximum, row["sha256"])
        core.need(len(raw) == row["size"], "sdk-tree-semantic-complete")
        self.check()
        return raw

    def semantics(self):
        raw = self.read_regular("sdk", "receipt.json", core.MAX_METADATA)
        core.need(core.sha(raw) == original.ORIGIN_PIN, "sdk-tree-qualified-fixed-original-recipe")
        recipe = core.decode(raw)
        reconstructed = core.expected_entries(recipe, raw, self.clock,
            self.expected[("sdk", "receipt.json")]["mode"],
            {name: self.expected[("sdk", "graph/" + name)]["mode"] for name in core.sdk.GRAPH})
        core.need(set(reconstructed) == set(self.expected) and all(all(
            self.expected[key].get(field) == value for field, value in row.items())
            for key, row in reconstructed.items()), "sdk-tree-qualified-original-complete-namespace")
        return core.encoded(original._semantic_export(self, recipe))

    def final(self):
        witnesses, nars = tree.scan_retained_tree(self.roots, self.expected, tree.PHYSICAL_POLICY, self.clock)
        core.need(witnesses == self.witnesses and nars == self.nars, "sdk-tree-qualified-current-final-proof")
        self.check()

    def fence(self):
        self.check()
        core.need(core._fresh_namespace(self.roots, tree.physical_expected(self.expected,
            tree.PHYSICAL_POLICY, self.clock), self.clock) == self.witnesses,
            "sdk-tree-qualified-last-physical-fence")
        self.check()

    def close(self):
        roots, self.roots = self.roots, {"sdk": None, "jdk": None}
        root, self.root = self.root, None
        alias_parent, self.alias_parent = self.alias_parent, None
        _drain(tuple(roots.values()) + (root, alias_parent))


def qualify(args):
    fields = ("MODE", "ENTRY_NS", "DEADLINE_NS", "EPOCH", "SOURCE_COMMIT", "GRAPH_SHA256")
    context = {name: os.environ.get("OMUX_NATIVE_SDK_TREE_" + name) for name in fields}
    entry, until = admission._context(context)
    clock = core.Clock((entry + 1170 * 10**9) / 10**9)
    clock.until_ns = entry + 1170 * 10**9
    core.need(entry <= core.time.monotonic_ns() < clock.until_ns, "sdk-tree-qualifier-original-clock")
    runfiles = Path(os.environ["TEST_SRCDIR"]).resolve(strict=True)
    fixed_data = runfiles / "_main/tools/retained-sdk-tree-data.json"
    core.need(args.data is not None and _execution_path(args.data) == fixed_data,
              "sdk-tree-qualifier-fixed-layout")
    creator = scan = output = None
    names = ("data", "context", "descriptor", "recipe", "inventory", "receipt", "extraction")
    owners = {name: None for name in names}
    raws = {}
    try:
        mapping = _read_small(runfiles / "_repo_mapping", clock, 1024 * 1024)
        rows = [row.split(",") for row in mapping.decode().splitlines()]
        core.need(all(len(row) == 3 for row in rows), "sdk-tree-qualifier-mapping")
        creator = admission.admit_carrier(runfiles, rows, context)
        core.need(type(creator) is admission.CreatorCarrierInputs, "sdk-tree-qualifier-real-provenance")
        clock = creator.clock
        owners["data"] = PublicInput(fixed_data, clock)
        raws["data"] = _capture_public(owners["data"], 65536)
        layout = admission._layout(raws["data"])
        tree_path = runfiles / layout["artifact"]["root"]
        base = tree_path.parent
        core.need(args.input_descriptor is not None and _execution_path(args.input_descriptor) == base / "declared-inputs.json",
                  "sdk-tree-qualifier-fixed-descriptor")
        paths = {"context": runfiles / layout["creator_context"], "recipe": runfiles / layout["recipe"],
            "inventory": runfiles / layout["artifact"]["inventory"],
            "receipt": runfiles / layout["artifact"]["receipt"],
            "descriptor": base / "declared-inputs.json", "extraction": tree_path / "extraction-receipt.json"}
        for name, path in paths.items():
            owners[name] = PublicInput(path, clock)
            raws[name] = _capture_public(owners[name], core.MAX_METADATA if name in ("recipe", "inventory", "descriptor") else 65536)
        core.need(core.decode(raws["context"]) == context, "sdk-tree-qualifier-same-creator-context")
        descriptor = _descriptor(raws["descriptor"], clock)
        # The action descriptor binds carrier logical aliases as well as its
        # execution-local names; only declared runfiles are read here.
        current = _runfiles_descriptor(descriptor, runfiles)
        recipe_raw, input_witnesses = _recipe(current, creator)
        core.need(recipe_raw == raws["recipe"], "sdk-tree-qualifier-complete-actual-recipe")
        selected = {"materialization": {"recipe_sha256": core.sha(recipe_raw),
            "action_inputs_sha256": core.sha(core.encoded(core.decode(recipe_raw)["inputs"]))}}
        admission.recipe(recipe_raw, selected, clock)
        logical, nars, lineage_raw = tree.parse_inventory(raws["inventory"], core.sha(raws["inventory"]), clock)
        inventory = core.decode(raws["inventory"])
        report = core.decode(raws["receipt"])
        expected_context = {"mode": tree.PROFILE, "epoch": context["EPOCH"], "source_commit": context["SOURCE_COMMIT"],
            "graph_sha256": context["GRAPH_SHA256"], "entry_monotonic_ns": entry,
            "deadline_monotonic_ns": until, "work_cutoff_monotonic_ns": clock.until_ns}
        keys = {"schema_version", "kind", "producer", "producer_context", "inventory", "tree_root",
            "extraction_receipt_sha256", "physical_mode_policy", "created_tree_commitment", "carrier_qualification",
            "materialization", "sdk_execution_qualified", "source_qualified", "compiler_qualified", "runtime_qualified"}
        core.need(type(report) is dict and set(report) == keys and core.encoded(report) == raws["receipt"]
            and type(report["schema_version"]) is int and report["schema_version"] == 1
            and report["kind"] == tree.REPORT_KIND and report["producer"] == tree.TARGET
            and report["producer_context"] == expected_context and report["tree_root"] == "tree"
            and report["physical_mode_policy"] == tree.PHYSICAL_POLICY
            and report["inventory"] == {"sha256": core.sha(raws["inventory"]), "bytes": len(raws["inventory"])}
            and report["carrier_qualification"] == creator.qualified
            and report["extraction_receipt_sha256"] == core.sha(raws["extraction"])
            and all(report[key] is False for key in ("sdk_execution_qualified", "source_qualified", "compiler_qualified", "runtime_qualified")),
            "sdk-tree-qualifier-closed-materialized-report")
        core.digest(report["created_tree_commitment"])
        core.need(report["materialization"] == {**selected["materialization"], "inventory_sha256": core.sha(raws["inventory"]),
            "sdk_nar": inventory["nars"]["sdk"], "jdk_nar": inventory["nars"]["jdk"]},
            "sdk-tree-qualifier-materialization-output-joins")
        files = {row["name"]: row["sha256"] for row in creator.qualified["report"]["files"]}
        core.need(core.decode(lineage_raw) == {"receipt_sha256": files["receipt.json"], "manifest_sha256": files["manifest.json"],
            "payload_sha256": files["payload.bin"], "origin_receipt_sha256": files["origin-receipt.json"]}
            and files["origin-receipt.json"] == original.ORIGIN_PIN, "sdk-tree-qualifier-authenticated-carrier-lineage")
        extraction = core.decode(raws["extraction"])
        core.need(type(extraction) is dict and set(extraction) == {"kind", "producer_context", "carrier_receipt_sha256",
            "origin_receipt_sha256", "manifest_sha256", "payload_sha256", "nars", "fresh_custody", "extracted_inventory_rechecked",
            "original_inodes_reused", "absolute_links_materialized_as_mounts", "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced"}
            and core.encoded(extraction) == raws["extraction"] and extraction["kind"] == core.EXTRACTED
            and extraction["carrier_receipt_sha256"] == creator.pin and extraction["nars"] == inventory["nars"]
            and extraction["origin_receipt_sha256"] == files["origin-receipt.json"]
            and extraction["manifest_sha256"] == files["manifest.json"] and extraction["payload_sha256"] == files["payload.bin"]
            and extraction["extracted_inventory_rechecked"] is True and all(extraction[key] is False for key in
                ("original_inodes_reused", "absolute_links_materialized_as_mounts", "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced")),
            "sdk-tree-qualifier-durable-extraction-lineage")
        scan = _TreeScan(tree_path, logical, clock)
        core.need(scan.nars == nars, "sdk-tree-qualifier-fresh-normalized-full-NAR")
        semantic = scan.semantics()
        output_base = core.absolute(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        output = admission._Directory(output_base, clock)
        os.mkdir("sdk-tree-public", mode=0o700, dir_fd=output.fd)
        output.close(); output = None
        output = admission._Directory(output_base / "sdk-tree-public", clock)
        written = {}
        for name, raw in (("receipt.json", raws["receipt"]), ("inventory.json", raws["inventory"]),
                          ("recipe.json", raws["recipe"]), ("creator-context.json", raws["context"])):
            written[name] = _write_leaf(output, name, raw, clock)
        _recheck_recipe(current, recipe_raw, input_witnesses, clock)
        creator.full()
        core.need(scan.semantics() == semantic, "sdk-tree-qualifier-final-semantic-readback")
        # Metadata and semantics work precedes the final complete current-tree
        # scan. Cheap held/named fences follow that last long IO, not a new clock.
        for name, owner in owners.items():
            core.need(_capture_public(owner, core.MAX_METADATA) == raws[name], "sdk-tree-qualifier-held-controls-readback")
        scan.final()
        _fence_recipe(current, input_witnesses, clock)
        creator.check()
        for owner in owners.values(): owner.check()
        for name, witness in written.items():
            core.need(core.identity(os.stat(name, dir_fd=output.fd, follow_symlinks=False)) == witness,
                      "sdk-tree-qualifier-output-name-fence")
        output.check(); scan.fence(); clock.tick()
    except BaseException as error:
        _drain(tuple(owners.values()) + (output, scan, creator), error)
        raise
    else:
        _drain(tuple(owners.values()) + (output, scan, creator))
        clock.tick()
        print("retained-sdk-tree: receipt-sha256=" + core.sha(raws["receipt"]), flush=True)
        clock.tick()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("materialize", "qualify"), required=True)
    for name in ("tree-output", "inventory-output", "receipt-output", "recipe-output", "creator-context", "input-descriptor"):
        parser.add_argument("--" + name)
    parser.add_argument("--data")
    args = parser.parse_args()
    if args.phase == "materialize":
        core.need(all(getattr(args, name.replace("-", "_")) for name in
            ("tree-output", "inventory-output", "receipt-output", "recipe-output", "creator-context", "input-descriptor")),
            "sdk-tree-materialize-arguments")
        core.need(args.data is None, "sdk-tree-materialize-no-qualifier-input")
        materialize(args)
    else:
        core.need(args.data is not None and args.input_descriptor is not None
            and all(getattr(args, name.replace("-", "_")) is None for name in
                ("tree-output", "inventory-output", "receipt-output", "recipe-output", "creator-context")),
            "sdk-tree-qualify-exact-arguments")
        qualify(args)


if __name__ == "__main__": main()
