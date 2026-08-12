const observer = @import("stage2_observer");
const build_options = @import("stage2_build_options");

test "emit candidate-bound Claude fake-upstream observations" {
    if (try observer.runLeaseChildSubprocessIfRequested()) return;
    try observer.emit(.{
        .candidate_sha = build_options.candidate_sha,
        .candidate_tree = build_options.candidate_tree,
        .workflow_run_id = build_options.workflow_run_id,
        .workflow_run_attempt = build_options.workflow_run_attempt,
        .gf_target_class = build_options.gf_target_class,
    });
}
