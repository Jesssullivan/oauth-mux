"""Actual closed selector declaration models; no selected host reads."""
load(":home_manager_bundle_repository.bzl", "bundle_configuration_valid")

def _impl(ctx):
    pending = {"schema_version": 1, "kind": "omux-home-manager-compact-input-configuration-v1", "status": "awaiting-qualified-bundle", "selection": None}
    row = {"root": "/home/jess/.local/state/omux-execution-20261005/model/test.outputs", "bundle_sha256": "a" * 64, "receipt_sha256": "b" * 64}
    selected = dict(pending, status = "selected-bundle", selection = row)
    cases = [(pending, True), (selected, True), (dict(pending, selection = row), False), (dict(selected, selection = None), False), (dict(selected, extra = True), False), (dict(selected, schema_version = True), False)]
    for root in ["/tmp/fixture", row["root"] + "/../escape", row["root"] + "/", row["root"] + "\n", row["root"] + "/a b", row["root"] + "/a\000b"]:
        cases.append((dict(selected, selection = dict(row, root = root)), False))
    for pin in ["a" * 63, "G" * 64, None, 1]:
        cases.append((dict(selected, selection = dict(row, bundle_sha256 = pin)), False))
        cases.append((dict(selected, selection = dict(row, receipt_sha256 = pin)), False))
    failures = [str(index) for index, case in enumerate(cases) if bundle_configuration_valid(case[0]) != case[1]]
    return [AnalysisTestResultInfo(success = not failures, message = "compact selector cases: " + ",".join(failures))]

home_manager_bundle_selection_test = rule(implementation = _impl, analysis_test = True)
