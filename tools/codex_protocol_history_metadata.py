"""Closed protocol/history generated Cargo-hub delta; no execution authority."""
import ast
import copy
import re

HUB = "rules_rs++crate+crates"
PACKAGE = "codex-rs/app-server-protocol"
ROLLOUT = "//codex-rs/rollout"
HISTORY = "//codex-rs/history"
MAX_HUB_FILE = 8 * 1024 * 1024
FIELDS = frozenset(("aliases","binaries","build_deps","build_deps_by_platform",
    "crate_features","crate_features_by_platform","deps","deps_by_platform",
    "dev_deps","dev_deps_by_platform","shared_libraries"))
LISTS = frozenset(("build_deps","crate_features","deps","dev_deps"))
PLATFORMS = frozenset(("build_deps_by_platform","crate_features_by_platform",
    "deps_by_platform","dev_deps_by_platform"))
MAPS = frozenset(("aliases","binaries","shared_libraries"))


def require(value):
    if value is not True:
        raise ValueError("protocol-history generated metadata differs")


def dep_data(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_HUB_FILE)
    tree = ast.parse(raw.decode("utf-8"))
    require(len(tree.body) == 1 and type(tree.body[0]) is ast.Assign
        and len(tree.body[0].targets) == 1
        and type(tree.body[0].targets[0]) is ast.Name
        and tree.body[0].targets[0].id == "DEP_DATA")
    nodes = list(ast.walk(tree))
    require(len(nodes) <= 100000)
    for node in nodes:
        if type(node) is ast.Dict:
            require(all(type(key) is ast.Constant and type(key.value) is str
                for key in node.keys))
            keys = [key.value for key in node.keys]
            require(len(keys) == len(set(keys)))
    data = ast.literal_eval(tree.body[0].value)
    require(type(data) is dict and 0 < len(data) <= 1000)
    for name,row in data.items():
        require(type(name) is str and not name.startswith("/")
            and all(part not in ("",".","..") for part in name.split("/"))
            and type(row) is dict and set(row) == FIELDS)
        for field in LISTS:
            require(type(row[field]) is list
                and all(type(value) is str for value in row[field])
                and len(row[field]) == len(set(row[field])))
        for field in PLATFORMS:
            require(type(row[field]) is dict and all(type(key) is str
                and type(values) is list and all(type(value) is str for value in values)
                and len(values) == len(set(values)) for key,values in row[field].items()))
        for field in MAPS:
            require(type(row[field]) is dict and all(type(key) is str and type(value) is str
                for key,value in row[field].items()))
    return data


def verify_hub_delta(before, after):
    # Unknown additional hub outputs stay byte-identical; none are invented.
    require(type(before) is dict and type(after) is dict and set(before) == set(after)
        and {"BUILD.bazel","defs.bzl","data.bzl"} <= set(before)
        and len(before) <= 16
        and all(type(name) is str and "/" not in name and name not in ("",".","..")
            and type(value) is bytes and len(value) <= MAX_HUB_FILE
            for files in (before,after) for name,value in files.items()))
    require(all(before[name] == after[name] for name in before if name != "data.bzl"))
    old, new = dep_data(before["data.bzl"]), dep_data(after["data.bzl"])
    require(PACKAGE in old and PACKAGE in new
        and old[PACKAGE]["deps"].count(ROLLOUT) == 1
        and old[PACKAGE]["deps"].count(HISTORY) == 1
        and old[PACKAGE]["aliases"].get(ROLLOUT) == "codex_rollout"
        and old[PACKAGE]["aliases"].get(HISTORY) == "codex_history")
    expected = copy.deepcopy(old)
    expected[PACKAGE]["deps"].remove(ROLLOUT)
    del expected[PACKAGE]["aliases"][ROLLOUT]
    # Includes every package, platform, feature, dev/build dependency and alias.
    require(new == expected)
    return True


def retained_overrides(repositories, export_root):
    """Omit exactly one hub; never omit spokes/module/tools/registry inputs."""
    require(type(export_root) is str and export_root.startswith("/")
        and "//" not in export_root and ".." not in export_root.split("/")
        and type(repositories) is dict and HUB in repositories
        and 0 < len(repositories) <= 1600)
    for name,directory in repositories.items():
        require(type(name) is str and re.fullmatch(r"[A-Za-z0-9._+~-]{1,256}",name) is not None
            and type(directory) is str and directory == export_root+"/repositories/"+name)
    return {name:directory for name,directory in repositories.items() if name != HUB}
