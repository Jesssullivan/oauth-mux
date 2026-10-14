"""Current SOURCE reader for a separately qualified public SDK TreeArtifact.

Expected-content authority comes only from the sealed successful-creator owner;
current physical/content authority is reestablished on this invocation. No flat
carrier byte verdict, SDK/SOURCE/compiler or native execution result is reused.
"""
import os
from pathlib import Path
import threading

import codex_native_sdk_carrier as core
import codex_original_sdk_inputs as original
import codex_native_file_writer_model_source as family
import codex_retained_sdk_tree_inputs as admission
import codex_retained_sdk_tree as tree

KIND = "omux-retained-current-sdk-tree-content-v1"


class HeldRetainedSdkTree:
    def __init__(self, runfiles, rows, entry, until, context, alias_owner):
        actual = original.validate_context(context)
        core.need(type(entry) is int and type(until) is int
            and int(actual["ENTRY_NS"]) == entry and int(actual["DEADLINE_NS"]) == until
            and until - entry == 1200 * 10**9 and type(alias_owner) is family.HeldControls
            and family.source.DEADLINE == (entry + 600 * 10**9) / 10**9,
            "retained-sdk-original-source-envelope")
        core.need(type(rows) is list and all(type(row) is list and len(row) == 3
            and all(type(value) is str for value in row) for row in rows),
            "retained-sdk-declared-mapping-rows")
        self.alias_owner = alias_owner
        self.runfiles = core.absolute(runfiles)
        self.rows = tuple(tuple(row) for row in rows)
        self.carrier_pin = None
        self.entry, self.until, self.cutoff = entry, until, entry + 600 * 10**9
        self.context = core.encoded(actual)
        self.inputs = None
        self.active = self.entered = self.finished = False
        self.pid, self.thread, self.self = os.getpid(), threading.get_ident(), self

    def __enter__(self):
        core.need(self.self is self and not self.entered, "retained-sdk-reentry")
        self.entered = self.active = True
        try:
            self.alias_owner.fence()
            runfiles = self.runfiles
            mapping = runfiles / "_repo_mapping"
            physical = mapping.resolve(strict=True)
            captured = [raw for name, raw in self.alias_owner.raws.items()
                if name == str(physical) and any(row[0] == mapping and row[1] == physical
                    for row in self.alias_owner.aliases)]
            core.need(len(captured) == 1 and 0 < len(captured[0]) <= 1024 * 1024,
                      "retained-sdk-declared-mapping-owner")
            rows = [line.split(",") for line in captured[0].decode().splitlines()]
            core.need(all(len(row) == 3 for row in rows)
                and tuple(tuple(row) for row in rows) == self.rows, "retained-sdk-mapping-shape")
            self.inputs = admission.admit(runfiles, rows, self.entry, self.until,
                core.decode(self.context), self.alias_owner)
            core.need(type(self.inputs) is admission.AuthenticatedTreeInputs,
                      "retained-sdk-authenticated-input-owner")
            # The input owner performs exactly one complete current initial
            # scan before return, retaining the same Root/clock/witness owners.
            selected = self.inputs
            self.clock = selected.clock
            self.roots = selected.roots
            self.expected = selected.logical
            self.witnesses = selected.witnesses
            self.nars = selected.nars
            self.sdk_root = selected.tree_root / "sdk"
            self.check()
            logical, nars, lineage = tree.parse_inventory(selected.inventory_raw,
                core.sha(selected.inventory_raw), self.clock)
            creator = core.decode(selected.receipt_raw)
            self.carrier_pin = core.decode(lineage)["receipt_sha256"]
            core.need(logical == self.expected and nars == self.nars
                and creator["carrier_qualification"]["report"]["carrier_receipt_sha256"] == self.carrier_pin
                and core.decode(lineage)["origin_receipt_sha256"] == original.ORIGIN_PIN,
                "retained-sdk-authenticated-logical-lineage")
            self.raw_original = self.read_regular("sdk", "receipt.json", core.MAX_METADATA)
            core.need(core.sha(self.raw_original) == original.ORIGIN_PIN,
                      "retained-sdk-original-recipe-pin")
            recipe = core.decode(self.raw_original)
            reconstructed = core.expected_entries(recipe, self.raw_original, self.clock,
                self.expected[("sdk", "receipt.json")]["mode"],
                {name: self.expected[("sdk", "graph/" + name)]["mode"] for name in core.sdk.GRAPH})
            core.need(set(reconstructed) == set(self.expected) and all(all(
                self.expected[key].get(field) == value for field, value in row.items())
                for key, row in reconstructed.items()), "retained-sdk-complete-original-reconstruction")
            self.original_mapping = core.encoded(original._semantic_export(self, recipe))
            self.fresh_mapping = core.encoded(self._mapping(recipe))
            self.fence()
            return self
        except BaseException as error:
            self.active = False
            try:
                if self.inputs is not None: self.inputs.close()
            except BaseException as cleanup:
                prior = BaseException.__cause__.__get__(error)
                raise error from (cleanup if prior is None else prior)
            raise

    def check(self):
        core.need(self.self is self and self.active and self.inputs is not None
            and os.getpid() == self.pid and threading.get_ident() == self.thread
            and self.clock.until_ns == self.cutoff and self.clock.deadline == self.cutoff / 10**9,
            "retained-sdk-current-owner-clock")
        self.clock.tick()
        current = {name: os.environ.get("OMUX_NATIVE_FILE_WRITER_MODELS_" + name)
            for name in original.CONTEXT_FIELDS}
        core.need(core.encoded(original.validate_context(current)) == self.context,
                  "retained-sdk-current-source-context")
        self.alias_owner.fence()
        self.inputs.check()
        core.need(set(self.roots) == {"sdk", "jdk"} and all(type(root) is core.Root
            and root.path == self.inputs.tree_root / role and root.clock is self.clock
            for role, root in self.roots.items()), "retained-sdk-same-current-roots")
        self.clock.tick()

    def read_regular(self, role, name, limit):
        self.check()
        key = (role, name)
        core.need(key in self.expected and self.expected[key]["kind"] == "file"
            and type(limit) is int and 0 < limit <= core.MAX_METADATA
            and self.expected[key]["size"] <= limit, "retained-sdk-selected-read")
        selected = self.expected[key]
        raw = core.read(self.roots[role], name, limit, selected["sha256"])
        core.need(len(raw) == selected["size"], "retained-sdk-selected-size")
        self.check()
        return raw

    def _mapping(self, recipe):
        old = core.decode(self.original_mapping)
        names = [row["canonical_name"] for row in recipe["repositories"]]
        core.need(len(names) == len(set(names)) and set(names) == set(old["repositories"]),
                  "retained-sdk-exact-repository-closure")
        repositories = {}
        for name in names:
            self.clock.tick()
            core.need(core.relative(name) == [name]
                and old["repositories"][name] == str(original.ORIGIN / "repositories" / name),
                "retained-sdk-original-repository-binding")
            repositories[name] = str(self.sdk_root / "repositories" / name)
        modules = {module: repositories[row["canonical_name"]]
            for module, row in recipe["modules"].items()}
        core.need(set(modules) == set(old["module_overrides"]) and all(
            old["module_overrides"][module] == str(original.ORIGIN / "repositories" /
                recipe["modules"][module]["canonical_name"]) for module in modules)
            and old["registry_cache"] == str(original.ORIGIN / "registry-cache"),
            "retained-sdk-original-module-registry-binding")
        self.clock.tick()
        return {"repositories": repositories, "module_overrides": modules,
            "inventory_sha256": old["inventory_sha256"], "mapping_sha256": old["mapping_sha256"],
            "graph_files": old["graph_files"], "registry_cache": str(self.sdk_root / "registry-cache"),
            "registry_inventory_sha256": old["registry_inventory_sha256"]}

    def mapping(self):
        self.check()
        result = core.decode(self.fresh_mapping)
        self.check()
        return result

    def qualification_record(self):
        self.check()
        result = self.inputs.qualification_record()
        core.need(type(result) is dict and set(result) == {"selector_sha256", "selection",
            "qualified_producer", "declaration", "proof_inputs"}, "retained-sdk-qualification-record")
        self.check()
        return result

    def record(self):
        self.check()
        result = {"kind": KIND, "custody": "current-complete-retained-public-sdk-tree",
            "creator": core.decode(self.inputs.receipt_raw),
            "inventory_sha256": core.sha(self.inputs.inventory_raw),
            "original_mapping": core.decode(self.original_mapping), "mapping": self.mapping(),
            "mapping_commitment_scope": "original-logical-recipe-preserved",
            "original_mapping_document_sha256": core.sha(self.original_mapping),
            "fresh_mapping_document_sha256": core.sha(self.fresh_mapping),
            "current_sdk_root": str(self.sdk_root), "current_jdk_root": str(self.inputs.tree_root / "jdk"),
            "physical_mode_policy": tree.PHYSICAL_POLICY,
            "consumer_context": core.decode(self.context), "complete_members": len(self.expected),
            "physical_paths_scope": "current-held-source-invocation-only",
            "downstream_requires_fresh_tree_proof": True, "consumer_copied_tree": False,
            "ambient_original_roots_read": False, "sdk_execution_qualified": False,
            "source_qualified": False, "compiler_qualified": False, "runtime_qualified": False}
        self.check()
        return result

    def fence(self):
        self.check()
        self.inputs.fence()
        self.alias_owner.fence()
        self.clock.tick()

    def finish(self):
        self.check()
        core.need(not self.finished, "retained-sdk-final-once")
        raw = self.read_regular("sdk", "receipt.json", core.MAX_METADATA)
        core.need(raw == self.raw_original and core.encoded(original._semantic_export(self,
            core.decode(raw))) == self.original_mapping and core.encoded(self._mapping(
                core.decode(raw))) == self.fresh_mapping, "retained-sdk-final-semantic-mapping")
        # Authentic creator/recipe/proof reads precede the owner's LAST complete
        # current tree SHA/NAR/namespace scan; its final physical fence follows.
        self.inputs.finish()
        self.fence()
        self.finished = True

    def close(self):
        core.need(self.self is self, "retained-sdk-foreign-close")
        owner, self.inputs = self.inputs, None
        self.active = False
        if owner is not None: owner.close()

    def __exit__(self, exc_type, error, trace):
        failure = error
        try:
            if exc_type is None:
                core.need(self.finished, "retained-sdk-final-required")
                self.fence()
        except BaseException as actual:
            failure = actual
            try: self.close()
            except BaseException as cleanup:
                prior = BaseException.__cause__.__get__(actual)
                raise actual from (cleanup if prior is None else prior)
            raise
        try: self.close()
        except BaseException as cleanup:
            if failure is not None:
                prior = BaseException.__cause__.__get__(failure)
                raise BaseException.with_traceback(failure, trace) from (cleanup if prior is None else prior)
            raise
        if exc_type is None: self.clock.tick()
        return False

    def __copy__(self): raise ValueError("retained SDK owner nontransferable")
    def __deepcopy__(self, memo): raise ValueError("retained SDK owner nontransferable")
    def __reduce_ex__(self, protocol): raise ValueError("retained SDK owner nontransferable")


def open_declared(runfiles, rows, entry, until, context, retained):
    return HeldRetainedSdkTree(runfiles, rows, entry, until, context, retained)


def record(session):
    core.need(type(session) is HeldRetainedSdkTree, "retained-sdk-record-owner")
    return session.record()


def regenerate(files, session, work, output, query_repository):
    import codex_native_carrier_metadata as metadata
    core.need(type(session) is HeldRetainedSdkTree, "retained-sdk-regeneration-owner")
    family.source.require(isinstance(query_repository, Path) and not work.exists())
    work.mkdir(mode=0o700)
    fd = family.source.write_source(work / "workspace", files)
    os.close(fd)
    for name in ("home", "home/cargo", "home/cache", "home/config", "home/state"):
        (work / name).mkdir(mode=0o700)
    tools = family.query_tools.verify_repository(query_repository, family.source.DEADLINE)
    family.source.require(tools["status"] == "declared-fixed-query-tools-byte-qualified"
        and tools["inputs_rechecked"] is True)
    old_hub = family.original_hub(session)
    mapping = session.mapping()
    plan = metadata.query_plan(work, work / "workspace/source", mapping, session.sdk_root)
    family.source.require(family.query.execute_query(plan, output) == 0)
    generated = family.query.read_hub(work / "output-base/external" / family.binding.metadata.HUB)
    family.verify_hub(old_hub, generated)
    family.source.verify_written(work / "workspace/source", files)
    family.source.require(family.query_tools.verify_repository(query_repository,
        family.source.DEADLINE) == tools and session.mapping() == mapping)
    return generated, plan, tools
