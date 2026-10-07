"""Exercise the actual inert repository selector, never selected input IO."""
load(":codex_live_fresh_runtime_repository.bzl", "runtime_selection")

def _impl(ctx):
    path = "/srv/fast-local/jess/state/codex/omux-native-candidate-20261007/fresh-runtime-selection.json"
    sha = "a" * 64
    expected = [path, sha, "17"]
    cases = [(path, sha, 17, ["", "", ""], expected),
             ("", "", 0, expected, expected)]
    # Every proper partial literal tuple refuses; zero tuple remains old env.
    for literal in [(path, "", 0), ("", sha, 0), ("", "", 17),
                    (path, sha, 0), (path, "", 17), ("", sha, 17)]:
        cases.append((literal[0], literal[1], literal[2], ["", "", ""], None))
    for environment in [(path, "", ""), ("", sha, ""), ("", "", "17"),
                        (path, sha, ""), (path, "", "17"), ("", sha, "17"), expected]:
        cases.append((path, sha, 17, environment, None))
    for environment in [("", "", ""), (path, "", "17"), (path, "G" * 64, "17"),
                        (path, sha, "-1"), (path, sha, "1.0")]:
        cases.append(("", "", 0, environment, None))
    for size in [-1, 16 * 1024 * 1024 + 1]:
        cases.append((path, sha, size, ["", "", ""], None))
    failures = []
    for index, case in enumerate(cases):
        if runtime_selection(case[0], case[1], case[2], case[3]) != case[4]:
            failures.append(str(index))
    return [AnalysisTestResultInfo(success = not failures,
        message = "fresh runtime selector case failures: " + ",".join(failures))]

codex_fresh_runtime_repository_selector_test = rule(implementation = _impl, analysis_test = True)
