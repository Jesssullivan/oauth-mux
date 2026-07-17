#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage:
  scripts/v02-benchmark-metrics-local.sh emit-missing <output.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
  scripts/v02-benchmark-metrics-local.sh verify <metrics.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
  scripts/v02-benchmark-metrics-local.sh require-incomplete <metrics.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
  scripts/v02-benchmark-metrics-local.sh require-pass <metrics.json> <candidate_sha> <candidate_tree> <workflow_run_id> <workflow_run_attempt> <gf_target_class>
USAGE
}

fail() {
  echo "v02-benchmark-metrics: $*" >&2
  exit 1
}

require_sha() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9a-f]{40}$ ]] ||
    fail "${label} must be exactly 40 lowercase hexadecimal characters"
}

require_positive_integer() {
  local label="$1"
  local value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || fail "${label} must be a positive integer"
}

validate_identity() {
  require_sha candidate_sha "$candidate_sha"
  require_sha candidate_tree "$candidate_tree"
  require_positive_integer workflow_run_id "$workflow_run_id"
  require_positive_integer workflow_run_attempt "$workflow_run_attempt"
  [ "$gf_target_class" = "tinyland-nix" ] || fail "unexpected gf_target_class"
}

verify_metrics() {
  [ -f "$metrics" ] || fail "benchmark metrics file is missing"
  validate_identity

  jq -s -e \
    --arg candidate_sha "$candidate_sha" \
    --arg candidate_tree "$candidate_tree" \
    --argjson workflow_run_id "$workflow_run_id" \
    --argjson workflow_run_attempt "$workflow_run_attempt" \
    --arg gf_target_class "$gf_target_class" \
    '
      def nonnegative_integer:
        ((type == "number") and (. >= 0) and (floor == .));
      def nonnegative_number:
        ((type == "number") and (. >= 0));
      def positive_number:
        ((type == "number") and (. > 0));
      def nonempty_string:
        ((type == "string") and (length > 0));
      def valid_status:
        ((. == "pass") or (. == "fail") or (. == "missing"));

      def latency_values_valid:
        ((.warmup_count | nonnegative_integer)
        and (.sample_count | nonnegative_integer)
        and (.p95_ms | nonnegative_number)
        and (.p99_ms | nonnegative_number)
        and (.p95_ms <= .p99_ms));
      def latency_passes:
        (latency_values_valid
        and (.warmup_count >= .min_warmup_count)
        and (.sample_count >= .min_sample_count)
        and (.p95_ms <= .max_p95_ms)
        and (.p99_ms <= .max_p99_ms));

      def throughput_values_valid:
        ((.direct_trial_count | nonnegative_integer)
        and (.broker_trial_count | nonnegative_integer)
        and (.trial_duration_seconds | nonnegative_integer)
        and (.direct_median_bytes_per_second | positive_number)
        and (.broker_median_bytes_per_second | nonnegative_number)
        and (.broker_to_direct_ratio | nonnegative_number)
        and (
          (.broker_median_bytes_per_second / .direct_median_bytes_per_second) as $computed
          | (.broker_to_direct_ratio - $computed) as $delta
          | (($delta >= -0.000001) and ($delta <= 0.000001))
        ));
      def throughput_passes:
        (throughput_values_valid
        and (.direct_trial_count >= .min_trial_count_per_path)
        and (.broker_trial_count >= .min_trial_count_per_path)
        and (.trial_duration_seconds == .required_trial_duration_seconds)
        and (.broker_to_direct_ratio >= .min_broker_to_direct_ratio));

      def idle_values_valid:
        ((.seconds_after_last_request | nonnegative_integer)
        and (.sample_count | nonnegative_integer)
        and (.sample_interval_seconds | nonnegative_integer)
        and (.max_rss_bytes | nonnegative_integer));
      def idle_passes:
        (idle_values_valid
        and (.seconds_after_last_request >= .required_idle_seconds)
        and (.sample_count == .required_sample_count)
        and (.sample_interval_seconds == .required_sample_interval_seconds)
        and (.max_rss_bytes <= .max_rss_limit_bytes));

      def replay_values_valid:
        ((.request_peak_bytes | nonnegative_integer)
        and (.sidecar_peak_bytes | nonnegative_integer)
        and (.host_peak_bytes | nonnegative_integer)
        and ((.budget_exhaustion_stream_once | type) == "boolean")
        and ((.no_request_bytes_persisted | type) == "boolean"));
      def replay_passes:
        (replay_values_valid
        and (.request_peak_bytes <= .request_limit_bytes)
        and (.sidecar_peak_bytes <= .sidecar_limit_bytes)
        and (.host_peak_bytes <= .host_limit_bytes)
        and (.budget_exhaustion_stream_once == true)
        and (.no_request_bytes_persisted == true));

      def cleanup_values_valid:
        (((.cleanup_completed | type) == "boolean")
        and (.stale_owner_count_after_cleanup | nonnegative_integer));
      def cleanup_passes:
        (cleanup_values_valid
        and (.cleanup_completed == true)
        and (.stale_owner_count_after_cleanup <= .max_stale_owner_count_after_cleanup));

      def fairness_values_valid:
        ((.session_count | nonnegative_integer)
        and (.account_count | nonnegative_integer)
        and (.cycles_per_session | nonnegative_integer)
        and (.lock_timeout_count | nonnegative_integer)
        and (.missed_completion_count | nonnegative_integer)
        and (.stale_owner_count_after_cleanup | nonnegative_integer)
        and (.max_minus_min_active_lease_load | nonnegative_integer));
      def fairness_passes:
        (fairness_values_valid
        and (.session_count == .required_session_count)
        and (.account_count == .required_account_count)
        and (.cycles_per_session >= .required_cycles_per_session)
        and (.lock_timeout_count == 0)
        and (.missed_completion_count == 0)
        and (.stale_owner_count_after_cleanup == 0)
        and (.max_minus_min_active_lease_load <= .max_active_lease_load_delta));

      if length != 1 then
        false
      else
        .[0] as $m
        | try (
            (($m | type) == "object")
            and (($m | keys) == [
              "candidate_sha",
              "candidate_tree",
              "clock_source",
              "gf_target_class",
              "measurements",
              "schema_version",
              "target",
              "workflow_run_attempt",
              "workflow_run_id",
              "workload_id"
            ])
            and ($m.schema_version == 1)
            and ($m.target == "v02-benchmark")
            and ($m.candidate_sha == $candidate_sha)
            and ($m.candidate_sha | test("^[0-9a-f]{40}$"))
            and ($m.candidate_tree == $candidate_tree)
            and ($m.candidate_tree | test("^[0-9a-f]{40}$"))
            and ($m.workflow_run_id == $workflow_run_id)
            and (($m.workflow_run_id | type) == "number")
            and ($m.workflow_run_attempt == $workflow_run_attempt)
            and (($m.workflow_run_attempt | type) == "number")
            and ($m.gf_target_class == $gf_target_class)
            and (($m.measurements | type) == "object")
            and (($m.measurements | keys) == [
              "concurrency_fairness",
              "idle_rss",
              "replay_memory",
              "routing_auth_latency",
              "stale_reservation_cleanup",
              "streaming_throughput"
            ])
            and (
              if all($m.measurements[]; .status == "missing") then
                (($m.clock_source == null) and ($m.workload_id == null))
              else
                (($m.clock_source | nonempty_string) and ($m.workload_id | nonempty_string))
              end
            )

            and ($m.measurements.routing_auth_latency as $x
              | (($x | keys) == [
                  "max_p95_ms",
                  "max_p99_ms",
                  "min_sample_count",
                  "min_warmup_count",
                  "p95_ms",
                  "p99_ms",
                  "sample_count",
                  "status",
                  "warmup_count"
                ])
              and ($x.status | valid_status)
              and ($x.min_warmup_count == 1000)
              and ($x.min_sample_count == 10000)
              and ($x.max_p95_ms == 5)
              and ($x.max_p99_ms == 10)
              and (
                (($x.status == "missing")
                  and ($x.warmup_count == null)
                  and ($x.sample_count == null)
                  and ($x.p95_ms == null)
                  and ($x.p99_ms == null))
                or (($x.status == "pass") and ($x | latency_passes))
                or (($x.status == "fail")
                  and ($x | latency_values_valid)
                  and (($x | latency_passes) == false))
              ))

            and ($m.measurements.streaming_throughput as $x
              | (($x | keys) == [
                  "broker_median_bytes_per_second",
                  "broker_to_direct_ratio",
                  "broker_trial_count",
                  "direct_median_bytes_per_second",
                  "direct_trial_count",
                  "min_broker_to_direct_ratio",
                  "min_trial_count_per_path",
                  "required_trial_duration_seconds",
                  "status",
                  "trial_duration_seconds"
                ])
              and ($x.status | valid_status)
              and ($x.min_trial_count_per_path == 5)
              and ($x.required_trial_duration_seconds == 30)
              and ($x.min_broker_to_direct_ratio == 0.95)
              and (
                (($x.status == "missing")
                  and ($x.direct_trial_count == null)
                  and ($x.broker_trial_count == null)
                  and ($x.trial_duration_seconds == null)
                  and ($x.direct_median_bytes_per_second == null)
                  and ($x.broker_median_bytes_per_second == null)
                  and ($x.broker_to_direct_ratio == null))
                or (($x.status == "pass") and ($x | throughput_passes))
                or (($x.status == "fail")
                  and ($x | throughput_values_valid)
                  and (($x | throughput_passes) == false))
              ))

            and ($m.measurements.idle_rss as $x
              | (($x | keys) == [
                  "max_rss_bytes",
                  "max_rss_limit_bytes",
                  "required_idle_seconds",
                  "required_sample_count",
                  "required_sample_interval_seconds",
                  "sample_count",
                  "sample_interval_seconds",
                  "seconds_after_last_request",
                  "status"
                ])
              and ($x.status | valid_status)
              and ($x.required_idle_seconds == 60)
              and ($x.required_sample_count == 5)
              and ($x.required_sample_interval_seconds == 1)
              and ($x.max_rss_limit_bytes == 20971520)
              and (
                (($x.status == "missing")
                  and ($x.seconds_after_last_request == null)
                  and ($x.sample_count == null)
                  and ($x.sample_interval_seconds == null)
                  and ($x.max_rss_bytes == null))
                or (($x.status == "pass") and ($x | idle_passes))
                or (($x.status == "fail")
                  and ($x | idle_values_valid)
                  and (($x | idle_passes) == false))
              ))

            and ($m.measurements.replay_memory as $x
              | (($x | keys) == [
                  "budget_exhaustion_stream_once",
                  "host_limit_bytes",
                  "host_peak_bytes",
                  "no_request_bytes_persisted",
                  "request_limit_bytes",
                  "request_peak_bytes",
                  "sidecar_limit_bytes",
                  "sidecar_peak_bytes",
                  "status"
                ])
              and ($x.status | valid_status)
              and ($x.request_limit_bytes == 33554432)
              and ($x.sidecar_limit_bytes == 67108864)
              and ($x.host_limit_bytes == 268435456)
              and (
                (($x.status == "missing")
                  and ($x.request_peak_bytes == null)
                  and ($x.sidecar_peak_bytes == null)
                  and ($x.host_peak_bytes == null)
                  and ($x.budget_exhaustion_stream_once == null)
                  and ($x.no_request_bytes_persisted == null))
                or (($x.status == "pass") and ($x | replay_passes))
                or (($x.status == "fail")
                  and ($x | replay_values_valid)
                  and (($x | replay_passes) == false))
              ))

            and ($m.measurements.stale_reservation_cleanup as $x
              | (($x | keys) == [
                  "cleanup_completed",
                  "max_stale_owner_count_after_cleanup",
                  "stale_owner_count_after_cleanup",
                  "status"
                ])
              and ($x.status | valid_status)
              and ($x.max_stale_owner_count_after_cleanup == 0)
              and (
                (($x.status == "missing")
                  and ($x.cleanup_completed == null)
                  and ($x.stale_owner_count_after_cleanup == null))
                or (($x.status == "pass") and ($x | cleanup_passes))
                or (($x.status == "fail")
                  and ($x | cleanup_values_valid)
                  and (($x | cleanup_passes) == false))
              ))

            and ($m.measurements.concurrency_fairness as $x
              | (($x | keys) == [
                  "account_count",
                  "cycles_per_session",
                  "lock_timeout_count",
                  "max_active_lease_load_delta",
                  "max_minus_min_active_lease_load",
                  "missed_completion_count",
                  "required_account_count",
                  "required_cycles_per_session",
                  "required_session_count",
                  "session_count",
                  "stale_owner_count_after_cleanup",
                  "status"
                ])
              and ($x.status | valid_status)
              and ($x.required_session_count == 20)
              and ($x.required_account_count == 50)
              and ($x.required_cycles_per_session == 100)
              and ($x.max_active_lease_load_delta == 1)
              and (
                (($x.status == "missing")
                  and ($x.session_count == null)
                  and ($x.account_count == null)
                  and ($x.cycles_per_session == null)
                  and ($x.lock_timeout_count == null)
                  and ($x.missed_completion_count == null)
                  and ($x.stale_owner_count_after_cleanup == null)
                  and ($x.max_minus_min_active_lease_load == null))
                or (($x.status == "pass") and ($x | fairness_passes))
                or (($x.status == "fail")
                  and ($x | fairness_values_valid)
                  and (($x | fairness_passes) == false))
              ))
          ) catch false
      end
    ' "$metrics" >/dev/null ||
    fail "benchmark metrics do not match the strict v0.2 G4 contract"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

mode="${1:-}"
metrics="${2:-}"
candidate_sha="${3:-}"
candidate_tree="${4:-}"
workflow_run_id="${5:-}"
workflow_run_attempt="${6:-}"
gf_target_class="${7:-}"

case "$mode" in
  emit-missing)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    validate_identity
    tmp_metrics="${metrics}.tmp.$$"
    trap 'rm -f "$tmp_metrics"' EXIT HUP INT TERM
    jq -n \
      --arg candidate_sha "$candidate_sha" \
      --arg candidate_tree "$candidate_tree" \
      --argjson workflow_run_id "$workflow_run_id" \
      --argjson workflow_run_attempt "$workflow_run_attempt" \
      --arg gf_target_class "$gf_target_class" \
      '{
        schema_version: 1,
        target: "v02-benchmark",
        candidate_sha: $candidate_sha,
        candidate_tree: $candidate_tree,
        workflow_run_id: $workflow_run_id,
        workflow_run_attempt: $workflow_run_attempt,
        gf_target_class: $gf_target_class,
        clock_source: null,
        workload_id: null,
        measurements: {
          routing_auth_latency: {
            status: "missing",
            warmup_count: null,
            sample_count: null,
            p95_ms: null,
            p99_ms: null,
            min_warmup_count: 1000,
            min_sample_count: 10000,
            max_p95_ms: 5,
            max_p99_ms: 10
          },
          streaming_throughput: {
            status: "missing",
            direct_trial_count: null,
            broker_trial_count: null,
            trial_duration_seconds: null,
            direct_median_bytes_per_second: null,
            broker_median_bytes_per_second: null,
            broker_to_direct_ratio: null,
            min_trial_count_per_path: 5,
            required_trial_duration_seconds: 30,
            min_broker_to_direct_ratio: 0.95
          },
          idle_rss: {
            status: "missing",
            seconds_after_last_request: null,
            sample_count: null,
            sample_interval_seconds: null,
            max_rss_bytes: null,
            required_idle_seconds: 60,
            required_sample_count: 5,
            required_sample_interval_seconds: 1,
            max_rss_limit_bytes: 20971520
          },
          replay_memory: {
            status: "missing",
            request_peak_bytes: null,
            sidecar_peak_bytes: null,
            host_peak_bytes: null,
            budget_exhaustion_stream_once: null,
            no_request_bytes_persisted: null,
            request_limit_bytes: 33554432,
            sidecar_limit_bytes: 67108864,
            host_limit_bytes: 268435456
          },
          stale_reservation_cleanup: {
            status: "missing",
            cleanup_completed: null,
            stale_owner_count_after_cleanup: null,
            max_stale_owner_count_after_cleanup: 0
          },
          concurrency_fairness: {
            status: "missing",
            session_count: null,
            account_count: null,
            cycles_per_session: null,
            lock_timeout_count: null,
            missed_completion_count: null,
            stale_owner_count_after_cleanup: null,
            max_minus_min_active_lease_load: null,
            required_session_count: 20,
            required_account_count: 50,
            required_cycles_per_session: 100,
            max_active_lease_load_delta: 1
          }
        }
      }' >"$tmp_metrics"
    mv "$tmp_metrics" "$metrics"
    trap - EXIT HUP INT TERM
    verify_metrics
    ;;

  verify)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    verify_metrics
    ;;

  require-incomplete)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    verify_metrics
    jq -e 'any(.measurements[]; ((.status == "fail") or (.status == "missing")))' \
      "$metrics" >/dev/null || fail "failed benchmark must contain incomplete metrics"
    ;;

  require-pass)
    [ "$#" -eq 7 ] || {
      usage
      exit 2
    }
    verify_metrics
    jq -e 'all(.measurements[]; .status == "pass")' "$metrics" >/dev/null || {
      jq -c '{
        schema_version: .schema_version,
        target: .target,
        result: "incomplete",
        measurements: [
          .measurements
          | to_entries[]
          | select(.value.status != "pass")
          | {id: .key, status: .value.status}
        ]
      }' "$metrics" >&2
      exit 3
    }
    ;;

  -h|--help|help)
    usage
    ;;

  *)
    usage
    exit 2
    ;;
esac
