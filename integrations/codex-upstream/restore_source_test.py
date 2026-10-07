"""Meaningful source-custody boundary predicates, without network or provider access."""

import os
import io
import tempfile
from contextlib import redirect_stderr
from pathlib import Path

from restore_source import OVERLAY_PATHS, batch_files, blob_hash, convenience_links, git_environment, overlay_changes, parse_arguments, private_root, safe_name, tree_entries, verify_packaged_base, verify_tree, write_receipt


def rejects(operation):
    try:
        operation()
    except (ValueError, FileExistsError):
        return
    raise AssertionError("invalid source custody accepted")


assert blob_hash(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"
oid = blob_hash(b"hello\n")
tree = f"100644 blob {oid}\tmain\0".encode()
entries = tree_entries(tree)
batch = f"{oid} blob 6\nhello\n\n".encode()
assert batch_files(entries, batch) == {"main": ("100644", b"hello\n")}
rejects(lambda: tree_entries(tree + tree))
rejects(lambda: tree_entries(tree.replace(oid.encode(), b"invalid")))
rejects(lambda: batch_files(entries, batch[:-1] + b"X"))
rejects(lambda: batch_files(entries, f"{oid} blob -1\n".encode()))
rejects(lambda: private_root(Path("/tmp/omux-forbidden-source"), create=True))
rejects(lambda: private_root(Path("/private/tmp/omux-forbidden-source"), create=True))
for name in ("../escape", "/absolute", "a/../escape", "a\\escape", "a\nfile"):
    rejects(lambda: safe_name(name))
env = git_environment(Path("/declared/root"), Path("/declared/ca"))
assert env["PATH"] == "" and env["GIT_CONFIG_GLOBAL"] == "/dev/null"
assert env["GIT_TERMINAL_PROMPT"] == "0" and "OPENAI_API_KEY" not in env
arguments = ["--artifact-dir", "/declared/artifact", "--git", "/declared/git",
             "--ca-file", "/declared/ca", "--root", "/declared/root"]
default = parse_arguments(arguments + ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output"])
assert default.bazel_configuration == "local_linux-fastbuild"
owner = parse_arguments(arguments + ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output",
                                     "--bazel-configuration", "owner-linux-fastbuild"])
assert owner.bazel_configuration == "owner-linux-fastbuild"
optimized = parse_arguments(arguments + ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output",
                                         "--bazel-configuration", "owner-linux-opt"])
assert optimized.bazel_configuration == "owner-linux-opt"
assert parse_arguments(arguments + ["--phase", "verify-prepared"]).bazel_configuration is None
for extra in (
        ["--phase", "verify-prepared", "--bazel-configuration", "owner-linux-fastbuild"],
        ["--phase", "verify-prepared", "--bazel-configuration", "owner-linux-opt"],
        ["--phase", "verify-prepared", "--bazel-configuration", "local_linux-fastbuild"],
        ["--phase", "prepare", "--bazel-output-base", "/declared/output", "--bazel-configuration", "owner-linux-fastbuild"],
        ["--phase", "prepare", "--bazel-output-base", "/declared/output", "--bazel-configuration", "owner-linux-opt"],
        ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output", "--bazel-configuration", "local_linux-opt"],
        ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output", "--bazel-configuration", "unknown-fastbuild"],
        ["--phase", "verify-prepared", "--bazel-output-base", "/declared/output", "--bazel-configuration", "../escape"]):
    with redirect_stderr(io.StringIO()):
        try:
            parse_arguments(arguments + extra)
        except SystemExit as error:
            assert error.code == 2
        else:
            raise AssertionError("invalid convenience-link configuration accepted")
overlay = "".join(f"diff --git a/{name} b/{name}\nindex 1111111..2222222 100644\n--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-old\n+new\n" for name in OVERLAY_PATHS)
assert overlay_changes(overlay.encode(), {name: b"old\n" for name in OVERLAY_PATHS}) == {name: b"new\n" for name in OVERLAY_PATHS}
rejects(lambda: overlay_changes(overlay.replace("-old", "-other").encode(), {name: b"old\n" for name in OVERLAY_PATHS}))
with tempfile.TemporaryDirectory() as temporary:
    source = Path(temporary)
    file = source / "main"
    file.write_bytes(b"verified")
    file.chmod(0o644)
    files = {"main": ("100644", b"verified")}
    verify_tree(source, files)
    manifest = {"files": {"main": {"before_sha256": __import__("hashlib").sha256(b"verified").hexdigest()}, "new": {"before_sha256": None}}}
    verify_packaged_base(files, {"main": b"verified"}, manifest)
    rejects(lambda: verify_packaged_base(files, {"main": b"other"}, manifest))
    rejects(lambda: verify_packaged_base({**files, "new": ("100644", b"unexpected")}, {"main": b"verified"}, manifest))
    alias = source / "alias"
    alias.symlink_to(source, target_is_directory=True)
    rejects(lambda: verify_tree(alias, files))
    alias.unlink()
    receipts = source / "receipts"
    receipts.mkdir(mode=0o700)
    target = source / "outside.json"
    target.write_text("untouched")
    (receipts / "receipt.json").symlink_to(target)
    rejects(lambda: write_receipt(receipts, "receipt.json", {"changed": True}))
    assert target.read_text() == "untouched"
    (receipts / "receipt.json").unlink()
    write_receipt(receipts, "receipt.json", {"verified": True})
    assert (receipts / "receipt.json").stat().st_mode & 0o777 == 0o600
    (receipts / "receipt.json").unlink()
    receipts.rmdir()
    target.unlink()
    with tempfile.TemporaryDirectory(dir=Path(os.environ["TEST_TMPDIR"]).resolve()) as output_temporary:
        output_base = Path(output_temporary)
        links = convenience_links(output_base)
        for name, target in links.items():
            (source / name).symlink_to(target)
        verify_tree(source, files, links)
        rejects(lambda: verify_tree(source, files))
        (source / "bazel-bin").unlink()
        (source / "bazel-bin").symlink_to(output_base / "wrong")
        rejects(lambda: verify_tree(source, files, links))
        (source / "bazel-bin").unlink()
        (source / "bazel-bin").write_text("not a link")
        rejects(lambda: verify_tree(source, files, links))
        for name in links:
            (source / name).unlink()
        owner_links = convenience_links(output_base, "owner-linux-fastbuild")
        assert owner_links["bazel-bin"].endswith("/bazel-out/owner-linux-fastbuild/bin")
        assert owner_links["bazel-testlogs"].endswith("/bazel-out/owner-linux-fastbuild/testlogs")
        for name, target in owner_links.items():
            (source / name).symlink_to(target)
        verify_tree(source, files, owner_links)
        rejects(lambda: verify_tree(source, files, links))
        (source / "bazel-bin").unlink()
        (source / "bazel-bin").symlink_to(output_base / "execroot/_main/bazel-out/owner-linux-fastbuild/foreign")
        rejects(lambda: verify_tree(source, files, owner_links))
        for name in owner_links:
            (source / name).unlink()
        optimized_links = convenience_links(output_base, "owner-linux-opt")
        assert optimized_links["bazel-bin"].endswith("/bazel-out/owner-linux-opt/bin")
        assert optimized_links["bazel-testlogs"].endswith("/bazel-out/owner-linux-opt/testlogs")
        for name, target in optimized_links.items():
            (source / name).symlink_to(target)
        verify_tree(source, files, optimized_links)
        rejects(lambda: verify_tree(source, files, owner_links))
        rejects(lambda: verify_tree(source, files, links))
        (source / "bazel-bin").unlink()
        (source / "bazel-bin").symlink_to(owner_links["bazel-bin"])
        rejects(lambda: verify_tree(source, files, optimized_links))
        for name in optimized_links:
            (source / name).unlink()
        rejects(lambda: convenience_links(output_base, "unknown-fastbuild"))
        rejects(lambda: convenience_links(output_base, "../escape"))
        (output_base / "execroot").symlink_to("/outside")
        rejects(lambda: convenience_links(output_base))
        rejects(lambda: convenience_links(output_base, "owner-linux-fastbuild"))
        rejects(lambda: convenience_links(output_base, "owner-linux-opt"))
        (output_base / "execroot").unlink()
        (output_base / "alternate").mkdir()
        (output_base / "execroot").symlink_to(output_base / "alternate")
        rejects(lambda: convenience_links(output_base))
        rejects(lambda: convenience_links(output_base, "owner-linux-opt"))
    file.write_bytes(b"altered")
    rejects(lambda: verify_tree(source, files))
    file.write_bytes(b"verified")
    file.chmod(0o755)
    rejects(lambda: verify_tree(source, files))
    file.chmod(0o644)
    file.chmod(0o664)
    rejects(lambda: verify_tree(source, files))
    file.chmod(0o644)
    (source / "extra").write_bytes(b"untracked")
    rejects(lambda: verify_tree(source, files))
    (source / "extra").unlink()
    (source / "escape").symlink_to("/outside")
    rejects(lambda: verify_tree(source, {**files, "escape": ("120000", b"/outside")}))
print("source custody: blob identity, path safety, isolated Git environment and complete blob/mode/symlink inventory passed")
