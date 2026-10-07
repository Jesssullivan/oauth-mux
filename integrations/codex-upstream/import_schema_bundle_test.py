"""R-N13: adversarial bounded import fixtures; no producer or provider execution."""

import os
import tempfile
from pathlib import Path

from import_schema_bundle import PREFIX, import_bundle, selected_outputs


def rejects(operation):
    try:
        operation()
    except (ValueError, OSError):
        return
    raise AssertionError("invalid schema custody accepted")


with tempfile.TemporaryDirectory(dir=Path(os.environ["TEST_TMPDIR"]).resolve()) as temporary:
    root = Path(temporary)
    stable, experimental, checkout = (root / name for name in ("stable", "experimental", "checkout"))
    for path in (stable, experimental, checkout):
        path.mkdir(mode=0o700)
    fixtures = {
        "typescript/v2/Owner.ts": b"export type Owner = string;\n",
        "json/v2/Owner.json": b'{"type":"string"}\n',
        "precomputed/app-server-exports-stable.json.zst": b"native-stable-compressed-bytes",
    }
    for name, value in fixtures.items():
        target = stable / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
        destination = checkout / PREFIX / name
        destination.parent.mkdir(parents=True, exist_ok=True)
    exp_name = "precomputed/app-server-exports-experimental.json.zst"
    (experimental / "precomputed").mkdir()
    (experimental / exp_name).write_bytes(b"native-experimental-compressed-bytes")
    unrelated = checkout / PREFIX / "json/v2/Unrelated.json"
    unrelated.write_bytes(b"unchanged")
    target = checkout / PREFIX / "json/v2/Owner.json"
    target.write_bytes(b"old-schema")
    outside = root / "outside"
    outside.write_bytes(b"do-not-overwrite")
    target.unlink()
    target.symlink_to(outside)
    rejects(lambda: import_bundle(stable, experimental, checkout, root / "refused",
                                 "12345678-1234-1234-1234-123456789abc"))
    assert outside.read_bytes() == b"do-not-overwrite" and not (root / "refused").exists()
    target.unlink()
    target.write_bytes(b"old-schema")
    extra = stable / "unexpected.txt"
    extra.write_bytes(b"foreign")
    rejects(lambda: selected_outputs(stable, experimental))
    extra.unlink()
    link = stable / "json/v2/Link.json"
    link.symlink_to(outside)
    rejects(lambda: selected_outputs(stable, experimental))
    link.unlink()
    rejects(lambda: import_bundle(stable, experimental, checkout, checkout / "receipt",
                                 "12345678-1234-1234-1234-123456789abc"))
    report = import_bundle(stable, experimental, checkout, root / "receipt",
                           "12345678-1234-1234-1234-123456789abc")
    assert report["file_count"] == 4 and report["normalization_performed"] is False
    assert report["compression_performed"] is False and report["native_support"] is False
    assert unrelated.read_bytes() == b"unchanged"
    for name, value in fixtures.items():
        assert (checkout / PREFIX / name).read_bytes() == value
    assert (checkout / PREFIX / exp_name).read_bytes() == (experimental / exp_name).read_bytes()
    assert (root / "receipt/schema-import-receipt.json").stat().st_mode & 0o777 == 0o600
    rejects(lambda: import_bundle(stable, experimental, checkout, root / "receipt",
                                 "12345678-1234-1234-1234-123456789abc"))

print("Schema import exact bytes, unrelated preservation, symlink rejection, overlap and exclusive receipt passed.")
