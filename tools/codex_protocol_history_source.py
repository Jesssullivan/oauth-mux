"""Produce one closed application dependency delta from pinned public C11 source.

No native execution or metadata regeneration occurs here. The distinct output
explicitly requires a newly qualified rules_rs/Cargo/Bzlmod SDK before builds.
"""
import json
import os
from pathlib import Path
import stat
import sys
import time

import codex_live_source as source

PARENT = Path("/home/jess/.local/state/omux-execution-20261005/cache-v2-4689a690587ec00080acae0eb6ba13df894a284b47e0ce7a6ee828bed0cb8d9d/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_live_source_producer/test.outputs/codex-live-source")
# Fixed current retained C11 public receipt custody; never chmod the input.
PARENT_RECEIPT_MODE = 0o555
PARENT_RECEIPT_SHA = "1e292ed6c2521b21a9d78d2c499df3cea70f6e0581e9daa946021eb83bbbd191"
PARENT_INVENTORY_SHA = "5e7628d20807b41c795d08d2ed6f0e6107d394b718f25dd22e9705206c38cc69"
PARENT_PATCHES = ["5b9eb9d8ffc19ac6e53429186b3dc3e51ab05ab9bbb30564c3b621d7d5383ef6","3851e3d5c1901cafa7cd0bae63a7ac84b1baac7b1f6be3102cc7b185e97ecd53","84ec6ddc333361b4785ac0c9b0a212ce7b25f200fb22c30eb0abdc21883c5ec5"]
PARENT_GRAPH = {".bazelrc":{"sha256":"7e48a0fffeb63df92029fe781deba5200f2c6a08f328ed9f3ac41ad471757a30"},".bazelversion":{"sha256":"cdecb300baad839a6f62791229f551a4fa33f3cbdca08e378dc976466354e778"},"MODULE.bazel":{"sha256":"1a6c8685d241a5390ff94432581e842c2950cbe5262b47b27d8db467cebec4c2"},"MODULE.bazel.lock":{"sha256":"3416c08d3ddff96ec9e0b76d7d89eaa2b75cc8d81f0a9f661d8b8466d1343657"},"codex-rs/Cargo.lock":{"sha256":"72efa81ed947d07ed4fbb3e10b094715ff00626126d758aaed56733c97887e5f"},"codex-rs/Cargo.toml":{"sha256":"c732c370ca012d0da7944d463601b3c834eb862a85866d3274db9d2acecea978"},"codex-rs/cli/BUILD.bazel":{"sha256":"2706cd57f6638a9046e1c2707f21c9d99f69788c62a28bc8d7e465ffe8f980b8"},"codex-rs/config/BUILD.bazel":{"sha256":"2b37d96cce0dad377a13e159439ca6a3e064cb3071ea5eaf1582633ac18699a5"},"codex-rs/core/BUILD.bazel":{"sha256":"338753d4f457505edbd9e42f7c22b28f2c1c13dd694b28d94d4d7c5226c031ce"},"codex-rs/core/Cargo.toml":{"sha256":"d745357079c9163f69cd60295f46962c342c80a9cbf11d42afd5b4941df1a6d3"},"codex-rs/login/BUILD.bazel":{"sha256":"8b3be99f128d9b2cf25d79c87acdc1aa8d1d8658b45e0b45a0502e710fc04573"},"defs.bzl":{"sha256":"e38193b7df27d444c9d4a0606207bd76f9226ba4f91ebd80935def0e5525e478"}}
PATCH_DIRECTORY = source.PATCH_DIRECTORY
PATCH_NAME = '2026-10-07-native-protocol-history-edge-formatted.UNAPPLIED.native.patch'
PATCH_SHA = 'b4dd868ac11d863f65e9fe3031d83b8fb7164a5551abca20dc46424c0465c48c'
PATCH_BYTES = "*** Begin Patch\n*** Update File: codex-rs/app-server-protocol/src/protocol/thread_history.rs\n@@\n use crate::protocol::v2::web_search_action_from_core;\n use codex_extension_items::image_generation::ImageGenerationItem;\n+use codex_history::CompactedItem;\n+use codex_history::RolloutItem;\n use codex_protocol::items::parse_hook_prompt_message;\n use codex_protocol::protocol::AgentMessageEvent;\n use codex_protocol::protocol::AgentReasoningEvent;\n@@\n #[cfg(test)]\n use codex_protocol::review_format::REVIEW_FALLBACK_MESSAGE;\n-use codex_rollout::CompactedItem;\n-use codex_rollout::RolloutItem;\n use std::collections::HashMap;\n use tracing::warn;\n use uuid::Uuid;\n@@\n     use crate::protocol::v2::CommandExecutionSource;\n     use codex_extension_items::ExtensionItem as CoreExtensionItem;\n     use codex_extension_items::sleep::SleepItem as CoreSleepItem;\n+    use codex_history::CompactedItem;\n     use codex_protocol::ThreadId;\n     use codex_protocol::dynamic_tools::DynamicToolCallOutputContentItem as CoreDynamicToolCallOutputContentItem;\n     use codex_protocol::items::CommandExecutionItem as CoreCommandExecutionItem;\n@@\n     use codex_protocol::protocol::UserMessageEvent;\n     use codex_protocol::protocol::WebSearchBeginEvent;\n     use codex_protocol::protocol::WebSearchEndEvent;\n-    use codex_rollout::CompactedItem;\n     use codex_utils_absolute_path::test_support::PathBufExt;\n     use codex_utils_absolute_path::test_support::test_path_buf;\n     use pretty_assertions::assert_eq;\n*** Update File: codex-rs/app-server-protocol/src/protocol/thread_history_projection.rs\n@@\n-use codex_protocol::protocol::EventMsg;\n-use codex_rollout::RolloutItem;\n+use codex_history::RolloutItem;\n-use codex_rollout::RolloutLine;\n+use codex_history::RolloutLine;\n+use codex_protocol::protocol::EventMsg;\n \n use crate::protocol::thread_history::ThreadHistoryChangeSet;\n use crate::protocol::thread_history::ThreadHistoryItemChange;\n*** Update File: codex-rs/app-server-protocol/src/protocol/thread_history_projection_tests.rs\n@@\n+use codex_history::CompactedItem;\n+use codex_history::RolloutItem;\n+use codex_history::RolloutLine;\n use codex_protocol::ThreadId;\n use codex_protocol::items::AgentMessageContent;\n use codex_protocol::items::AgentMessageItem;\n@@\n use codex_protocol::protocol::TurnStartedEvent;\n use codex_protocol::security_risk::SecurityRiskScore;\n use codex_protocol::user_input::UserInput;\n-use codex_rollout::CompactedItem;\n-use codex_rollout::RolloutItem;\n-use codex_rollout::RolloutLine;\n use pretty_assertions::assert_eq;\n use std::collections::BTreeMap;\n \n*** Update File: codex-rs/app-server-protocol/src/protocol/item_builders_tests.rs\n@@\n use super::*;\n use crate::protocol::thread_history::build_turns_from_rollout_items;\n+use codex_history::RolloutItem;\n use codex_protocol::protocol::EventMsg;\n use codex_protocol::protocol::ExecCommandSource;\n use codex_protocol::protocol::GuardianAssessmentStatus;\n use codex_protocol::protocol::TurnStartedEvent;\n-use codex_rollout::RolloutItem;\n use pretty_assertions::assert_eq;\n use serde_json::json;\n \n*** Update File: codex-rs/app-server-protocol/Cargo.toml\n@@\n codex-history = { workspace = true }\n codex-protocol = { workspace = true }\n-codex-rollout = { workspace = true }\n codex-secrets = { workspace = true }\n codex-shell-command = { workspace = true }\n codex-utils-absolute-path = { workspace = true }\n*** Update File: codex-rs/Cargo.lock\n@@\n [[package]]\n name = \"codex-app-server-protocol\"\n version = \"0.0.0\"\n dependencies = [\n  \"anyhow\",\n  \"codex-app-server-protocol-noop-macros\",\n  \"codex-experimental-api-macros\",\n  \"codex-extension-items\",\n  \"codex-history\",\n  \"codex-protocol\",\n- \"codex-rollout\",\n  \"codex-secrets\",\n  \"codex-shell-command\",\n  \"codex-utils-absolute-path\",\n*** End Patch\n".encode()
KIND = 'omux-native-protocol-history-source-v1'
RUST_PATHS = {
    'codex-rs/app-server-protocol/src/protocol/thread_history.rs': 3,
    'codex-rs/app-server-protocol/src/protocol/thread_history_projection.rs': 2,
    'codex-rs/app-server-protocol/src/protocol/thread_history_projection_tests.rs': 3,
    'codex-rs/app-server-protocol/src/protocol/item_builders_tests.rs': 1,
}
MANIFEST = 'codex-rs/app-server-protocol/Cargo.toml'
LOCK = 'codex-rs/Cargo.lock'
ALLOWED = frozenset((*RUST_PATHS, MANIFEST, LOCK))
GRAPH = (*source.GRAPH, MANIFEST, 'codex-rs/app-server-protocol/BUILD.bazel',
         'codex-rs/history/Cargo.toml')
PHASE = 'parent'
PHASES = frozenset(('parent','patch','dependency','output'))


def require(value):
    source.require(value)


IMPORT_GROUPS = {
    'codex-rs/app-server-protocol/src/protocol/thread_history.rs': (
        (b'use codex_protocol::items::parse_hook_prompt_message;',
         (b'use codex_history::CompactedItem;',b'use codex_history::RolloutItem;')),
        (b'    use codex_protocol::ThreadId;', (b'    use codex_history::CompactedItem;',))),
    'codex-rs/app-server-protocol/src/protocol/thread_history_projection.rs': (
        (b'use codex_protocol::protocol::EventMsg;',
         (b'use codex_history::RolloutItem;',b'use codex_history::RolloutLine;')),),
    'codex-rs/app-server-protocol/src/protocol/thread_history_projection_tests.rs': (
        (b'use codex_protocol::ThreadId;',
         (b'use codex_history::CompactedItem;',b'use codex_history::RolloutItem;',
          b'use codex_history::RolloutLine;')),),
    'codex-rs/app-server-protocol/src/protocol/item_builders_tests.rs': (
        (b'use codex_protocol::protocol::EventMsg;', (b'use codex_history::RolloutItem;',)),),
}


def order_history_imports(name, value):
    # Move only nine known imports within their five declared existing groups.
    # Blank boundaries, cfg attributes and every unrelated line stay exact.
    blocks = value.split(b'\n\n')
    for anchor,imports in IMPORT_GROUPS[name]:
        selected = [index for index,block in enumerate(blocks) if anchor in block.split(b'\n')]
        require(len(selected) == 1)
        index = selected[0]
        lines = blocks[index].split(b'\n')
        require(all(lines.count(line) == 1 for line in imports)
            and tuple(line for line in lines if b'use codex_history::' in line) == imports)
        retained = [line for line in lines if line not in imports]
        position = retained.index(anchor)
        require(position == 0 or not retained[position-1].strip().startswith(b'#['))
        blocks[index] = b'\n'.join(retained[:position]+list(imports)+retained[position:])
    return b'\n\n'.join(blocks)


def read_parent_receipt():
    """Read the pinned current C11 metadata; full source proof follows separately."""
    root = source.directory(PARENT)
    try:
        raw, mode = source.read(root, 'source-receipt.json', source.MAX_METADATA)
    finally:
        os.close(root)
    require(mode == PARENT_RECEIPT_MODE and source.sha(raw) == PARENT_RECEIPT_SHA)
    receipt = json.loads(raw, object_pairs_hook=source.unique)
    require(type(receipt['schema_version']) is int and receipt['schema_version'] == 1
        and receipt['status'] == 'verified-fresh-native-candidate'
        and receipt['commit'] == source.COMMIT
        and receipt['baseline_receipt_sha256'] == source.BASE_RECEIPT_SHA
        and receipt['baseline_inventory_sha256'] == source.BASE_INVENTORY
        and receipt['patch_sha256'] == PARENT_PATCHES
        and receipt['inventory_sha256'] == PARENT_INVENTORY_SHA
        and receipt['graph_files'] == PARENT_GRAPH
        and receipt['native_support'] is False
        and receipt['native_compile_passed'] is False
        and receipt['provider_evaluation'] is False)
    return receipt


def load_parent():
    receipt = read_parent_receipt()
    inventory = receipt['source_inventory']
    require(isinstance(inventory,dict) and len(inventory) == 8549
        and type(receipt['tracked_files']) is int and receipt['tracked_files'] == 8549
        and source.sha(source.canonical(inventory)) == PARENT_INVENTORY_SHA)
    files, total = {}, 0
    for name, row in sorted(inventory.items()):
        source.safe_name(name)
        require(isinstance(row,dict) and set(row) == {'mode','sha256'}
            and row['mode'] in ('100644','100755','120000')
            and source.HASH.fullmatch(row['sha256']))
        fd = source.directory(PARENT / 'source' / str(Path(name).parent))
        try:
            if row['mode'] == '120000':
                before = os.stat(Path(name).name, dir_fd=fd, follow_symlinks=False)
                require(stat.S_ISLNK(before.st_mode) and before.st_uid == os.getuid())
                value = os.readlink(Path(name).name, dir_fd=fd).encode()
                after = os.stat(Path(name).name, dir_fd=fd, follow_symlinks=False)
                require((before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)
                    == (after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns))
            else:
                value, mode = source.read(fd, Path(name).name, source.MAX_SOURCE)
                require(mode == 0o555)
        finally:
            os.close(fd)
        total += len(value)
        require(total <= source.MAX_SOURCE and source.sha(value) == row['sha256'])
        files[name] = (row['mode'],value)
    require(type(receipt['source_bytes']) is int and receipt['source_bytes'] == total)
    require(all({'sha256':source.sha(files[name][1])} == PARENT_GRAPH[name]
        for name in source.GRAPH))
    # Full sealed named tree readback also refuses extra/unselected source files.
    source.verify_written(PARENT / 'source',files)
    return files, receipt


def transform(files, raw):
    require(type(raw) is bytes and raw == PATCH_BYTES and source.sha(raw) == PATCH_SHA)
    result = dict(files)
    require(ALLOWED <= set(result)
        and all(result[name][0] == '100644' for name in ALLOWED))
    for name,count in RUST_PATHS.items():
        value = result[name][1]
        require(value.count(b'codex_rollout::') == count)
        for line in value.splitlines():
            if b'codex_rollout::' in line:
                require(line.strip() in (b'use codex_rollout::CompactedItem;',
                    b'use codex_rollout::RolloutItem;',b'use codex_rollout::RolloutLine;'))
        result[name] = ('100644',order_history_imports(name,
            value.replace(b'codex_rollout::',b'codex_history::')))
    mode,value = result[MANIFEST]
    remove = b'codex-rollout = { workspace = true }\n'
    require(value.count(remove) == 1
        and value.count(b'codex-history = { workspace = true }\n') == 1)
    result[MANIFEST] = (mode,value.replace(remove,b'',1))
    mode,value = result[LOCK]
    header = b'[[package]]\nname = "codex-app-server-protocol"\nversion = "0.0.0"\ndependencies = [\n'
    require(value.count(header) == 1)
    start = value.index(header)
    end = value.find(b'\n[[package]]\n',start+len(header))
    require(end >= 0)
    block = value[start:end]
    require(block.count(b' "codex-rollout",\n') == 1
        and block.count(b' "codex-history",\n') == 1)
    result[LOCK] = (mode,value[:start]+block.replace(b' "codex-rollout",\n',b'',1)+value[end:])
    validate_transition(files,result)
    return result


def validate_transition(before, after):
    require(set(before) == set(after)
        and {name for name in before if before[name] != after[name]} == ALLOWED
        and all(before[name][0] == after[name][0] for name in before)
        and all(before[name] == after[name] for name in before if name not in ALLOWED))
    require(all(before[name] == after[name] for name in source.GRAPH if name != LOCK)
        and before[LOCK][1].count(b' "codex-rollout",\n')
            == after[LOCK][1].count(b' "codex-rollout",\n')+1)
    # Build/workspace declarations remain exact: regenerated all_crate_deps
    # must reflect the manifest/lock removal, without handwritten overrides.
    for name in ('codex-rs/app-server-protocol/BUILD.bazel','codex-rs/Cargo.toml',
            'codex-rs/history/Cargo.toml'):
        require(before[name] == after[name])


def produce(output,seconds):
    global PHASE
    require(type(seconds) is int and 1 <= seconds <= 840)
    source.DEADLINE = time.monotonic()+seconds
    PHASE = 'parent'
    files,parent = load_parent()
    PHASE = 'patch'
    fd = source.directory(PATCH_DIRECTORY)
    try:raw,_ = source.read(fd,PATCH_NAME,source.MAX_PATCH)
    finally:os.close(fd)
    changed = transform(files,raw)
    PHASE = 'dependency'
    inventory = {name:{'mode':mode,'sha256':source.sha(value)}
        for name,(mode,value) in changed.items()}
    receipt = {'schema_version':1,'kind':KIND,
        'status':'verified-protocol-history-source-pending-sdk-metadata',
        'commit':source.COMMIT,'parent_source_root':str(PARENT),
        'parent_source_receipt_sha256':PARENT_RECEIPT_SHA,
        'parent_source_inventory_sha256':PARENT_INVENTORY_SHA,
        'patch_sha256':PARENT_PATCHES+[PATCH_SHA],
        'patches':parent['patches']+[{'patch_sha256':PATCH_SHA,'paths':sorted(ALLOWED)}],
        'source_inventory':inventory,'inventory_sha256':source.sha(source.canonical(inventory)),
        'tracked_files':len(changed),'source_bytes':sum(len(value) for _,value in changed.values()),
        'graph_files':{name:{'sha256':source.sha(changed[name][1])} for name in GRAPH},
        'parent_graph_files':{name:{'sha256':source.sha(files[name][1])} for name in GRAPH},
        'physical_mode_policy':'bazel-retained-export-all-regular-and-directories-0555-v1',
        'dependency_change':{'package':'codex-app-server-protocol','removed_normal':'codex-rollout',
            'existing_normal':'codex-history','changed_paths':sorted(ALLOWED)},
        'graph_resolution':'new-rules-rs-metadata-and-sdk-export-required',
        'sdk_metadata_qualified':False,'native_support':False,
        'native_compile_passed':False,'provider_evaluation':False}
    PHASE = 'output'
    root = source.write_source(output,changed)
    try:
        fd = os.open('source-receipt.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,
            0o600,dir_fd=root)
        with os.fdopen(fd,'wb') as stream:
            stream.write(source.encoded(receipt));stream.flush()
            os.fchmod(stream.fileno(),0o444);os.fsync(stream.fileno())
        os.fsync(root);os.fchmod(root,0o555)
    finally:os.close(root)
    return receipt


def main():
    require(len(sys.argv) == 1 and os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR')
        and os.environ.get('TEST_TIMEOUT'))
    seconds = min(840,int(os.environ['TEST_TIMEOUT'])-60)
    root = Path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR']).resolve(strict=True)
    produce(root/'protocol-history-source',seconds)
    print('protocol history source produced; SDK metadata and native compilation unrun')


if __name__ == '__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,json.JSONDecodeError):
        print('protocol history source refused at '+(PHASE if PHASE in PHASES else 'parent'),
            file=sys.stderr)
        raise SystemExit(1) from None
