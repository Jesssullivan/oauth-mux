"""Provider-free predicates only; never invokes a daemon, native process or provider."""
import copy
import json
import hashlib
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import test_installed_codex_live_continuity as fixture

def receipt():
    return {
        "schema_version": 1,
        "scope": "operator_drain_same_process_completed_turn_substitution",
        "transition_reason": "operator_drain", "application": "omux-maintained-codex",
        "application_version": "0.157.0", "model": "fixture-model", "provider_usage_records": 2,
        "native_context_mode": "text_transcript_v1", "reasoning_summary": "none", "reasoning_effort": "low",
        "minimum_reasoning_effort_verified": True, "native_detach_proven": False,
        "integration_restoration_proven": False,
        "upstream_commit": "a" * 40, "candidate_patch_sha256": "b" * 64,
        "runtime_archive_sha256": "c" * 64, "accounts": ["account_a", "account_b"],
        "submitted_turns": 2, "accepted_completed_turns": 2, "tool_calls": 0,
        "same_process": True, "same_native_owner": True, "same_native_thread": True,
        "native_store_identity_preserved": True, "accepted_history_prefix_preserved": True,
        "accepted_work_repeated": False, "empty_native_resume_checkpoint_proven": True,
        "accepted_history_cold_resume_proven": False, "provider_rejection_handoff_proven": False,
        "concurrent_handoff_proven": False, "full_native_account_lifecycle_proven": False,
    }

def history(events):
    return ((), (), b"", b"".join(json.dumps(item).encode() + b"\n" for item in events))

def completed_events():
    return [
        {"type": "response_item", "payload": {"type": "message", "role": "user",
                                             "content": [{"type": "input_text", "text": "fixture prompt"}]}},
        {"type": "response_item", "payload": {"type": "message", "role": "assistant",
                                             "content": [{"type": "output_text", "text": "OMUX_A_DONE"}]}},
        {"type": "token_usage_record", "payload": {}},
        {"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "OMUX_A_DONE"}},
    ]

class LiveContractTest(unittest.TestCase):
    def setUp(self):
        self.scenario = fixture.LiveScenario({"model": "fixture-model", "authorized_source_paths": []})
        self.previous = history([])

    def complete(self, events):
        return self.scenario.completed_text(history(events), self.previous, "OMUX_A_DONE", "fixture prompt")

    def native_context(self, role, kinds):
        return {"type": "response_item", "payload": {
            "type": "message", "role": role,
            "content": [{"type": "input_text", "text": "synthetic context " + str(index)}
                        for index, _ in enumerate(kinds)],
            "internal_chat_message_metadata_passthrough": {"content_item_kinds": kinds},
        }}

    def test_first_real_turn_retains_qualified_native_context_without_counting_extra_human_input(self):
        context = [
            self.native_context("developer", ["permissions.instructions", "environments.instructions"]),
            self.native_context("user", ["agents_md.instructions", "environments.environment_context"]),
        ]
        events = context + completed_events()
        before = copy.deepcopy(events)
        self.assertTrue(self.complete(events))
        self.assertEqual(events, before)

    def test_exact_nonce_prompt_is_required_independent_of_optional_native_input_order(self):
        first = fixture.submitted_text_prompt("OMUX_A_DONE", "1" * 32)
        second = fixture.submitted_text_prompt("OMUX_A_DONE", "2" * 32)
        self.assertNotEqual(first, second)
        events = completed_events()
        events[0]["payload"]["content"][0]["text"] = first
        self.assertTrue(self.scenario.completed_text(history(events), self.previous, "OMUX_A_DONE", first))
        events[0]["metadata"] = {"user_input_order": 0}
        self.assertTrue(self.scenario.completed_text(history(events), self.previous, "OMUX_A_DONE", first))
        with self.assertRaises(ValueError):
            self.scenario.completed_text(history(events), self.previous, "OMUX_A_DONE", second)
        for nonce in ("short", "z" * 32):
            with self.assertRaises(ValueError):
                fixture.submitted_text_prompt("OMUX_A_DONE", nonce)

    def test_context_annotations_are_role_bound_and_complete(self):
        accepted = self.native_context("developer", ["permissions.instructions"])
        mutations = []
        missing = copy.deepcopy(accepted)
        del missing["payload"]["internal_chat_message_metadata_passthrough"]
        mutations.append(missing)
        for kinds in ([], ["unknown"], ["permissions.instructions", "environments.instructions"],
                      ["agents_md.instructions"], ["arbitrary_extension.instructions"]):
            changed = copy.deepcopy(accepted)
            changed["payload"]["internal_chat_message_metadata_passthrough"]["content_item_kinds"] = kinds
            mutations.append(changed)
        for mutation in mutations:
            with self.subTest(context=mutation), self.assertRaises(ValueError):
                self.complete([mutation] + completed_events())

    def test_native_context_cannot_mask_extra_user_prompt_or_tool_metadata(self):
        accepted = self.native_context("user", ["environments.environment_context"])
        mutations = []
        for field, value in (("client_authored", True), ("user_input_order", 0),
                             ("inherited_user_message", True), ("sender_user_messages", {}),
                             ("delivered_assistant_message", "already executed")):
            changed = copy.deepcopy(accepted)
            changed["metadata"] = {field: value}
            mutations.append(changed)
        for field, value in (("cell_id", "synthetic-cell"), ("executed_tool_calls", []),
                             ("tool_calls_complete", False)):
            changed = copy.deepcopy(accepted)
            changed["payload"]["internal_chat_message_metadata_passthrough"][field] = value
            mutations.append(changed)
        for mutation in mutations:
            with self.subTest(context=mutation), self.assertRaises(ValueError):
                self.complete([mutation] + completed_events())
        extra = copy.deepcopy(completed_events()[0])
        extra["payload"]["content"][0]["text"] = "unexpected human input"
        with self.assertRaises(ValueError):
            self.complete([extra] + completed_events())

    def test_context_shaped_exact_prompt_cannot_impersonate_human_submission(self):
        events = completed_events()
        events[0]["payload"]["internal_chat_message_metadata_passthrough"] = {
            "content_item_kinds": ["environments.environment_context"]}
        with self.assertRaises(ValueError):
            self.complete(events)

    def terminal_constructor(self, *, cli_overrides=None, resume=None):
        launch = mock.Mock(return_value=mock.Mock(pid=123))
        observer = mock.Mock()
        profile = {} if cli_overrides is None else {"cli_overrides": cli_overrides}
        with mock.patch.object(fixture.tui.pty, "openpty", return_value=(101, 102)), \
             mock.patch.object(fixture.tui.fcntl, "ioctl"), \
             mock.patch.object(fixture.tui.os, "set_blocking"), \
             mock.patch.object(fixture.tui.os, "close"), \
             mock.patch.object(fixture.tui.selectors, "DefaultSelector"):
            terminal = fixture.tui.TerminalProcess(
                Path("/fixture/candidate"), {"TERM": "fixture"}, Path("/fixture/work"),
                resume=resume, popen_factory=launch,
                failure_observer=observer, **profile)
        self.assertIs(terminal.failure_observer, observer)
        self.assertIs(terminal.process, launch.return_value)
        return launch.call_args

    def test_actual_constructor_preserves_default_and_optional_hooks(self):
        called = self.terminal_constructor()
        command = called.args[0]
        self.assertIn("--pty-exec", command)
        self.assertNotIn("--cli-overrides", command)
        self.assertTrue(called.kwargs["start_new_session"])
        self.assertEqual(0o077, called.kwargs["umask"])

    def test_actual_constructor_carries_only_explicit_selected_profile(self):
        selected = ('omux_broker.context_mode="text_transcript_v1"',
                    'model_reasoning_summary="none"', 'model_reasoning_effort="low"')
        resume = "11111111-1111-1111-1111-111111111111"
        called = self.terminal_constructor(cli_overrides=selected, resume=resume)
        command = called.args[0]
        self.assertEqual(resume, command[-3])
        self.assertEqual("--cli-overrides", command[-2])
        self.assertEqual(list(selected), json.loads(command[-1]))

    def test_actual_pty_exec_rejects_widened_profile_before_native_exec(self):
        selected = ['omux_broker.context_mode="text_transcript_v1"',
                    'model_reasoning_summary="auto"', 'model_reasoning_effort="low"']
        arguments = ["fixture.py", "--pty-exec", "/fixture/candidate", "/fixture/work", "123",
                     "--cli-overrides", json.dumps(selected)]
        libc = mock.Mock()
        libc.prctl.return_value = 0
        with mock.patch.object(fixture.tui.sys, "argv", arguments), \
             mock.patch.object(Path, "resolve", lambda self, **kwargs: self), \
             mock.patch.object(fixture.tui.os, "getppid", return_value=123), \
             mock.patch.object(fixture.tui.os, "chdir"), \
             mock.patch.object(fixture.tui.os, "execve") as native_exec, \
             mock.patch.object(fixture.tui.ctypes, "CDLL", return_value=libc), \
             mock.patch.object(fixture.tui.fcntl, "ioctl"):
            with self.assertRaises(ValueError):
                fixture.tui.main()
            native_exec.assert_not_called()

    def test_narrow_receipt_accepts_closed_predicates(self):
        fixture.validate_receipt(receipt())

    def test_fresh_receipt_retains_three_patch_chain_without_forging_old_candidate_identity(self):
        value = receipt()
        del value["candidate_patch_sha256"]
        value.update(runtime_kind=fixture.FRESH_KIND, candidate_patch_sha256s=["b" * 64, "d" * 64, "e" * 64])
        fixture.validate_receipt(value)
        for field, replacement in (("runtime_kind", "retained"), ("candidate_patch_sha256s", ["b" * 64]),
                                   ("candidate_patch_sha256s", ["b" * 64, "d" * 64, "bad"])):
            invalid = {**value, field: replacement}
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.validate_receipt(invalid)
        with self.assertRaises(ValueError):
            fixture.validate_receipt({**value, "candidate_patch_sha256": "b" * 64})

    def test_protocol_history_receipt_accepts_only_the_exact_new_four_patch_identity(self):
        value = receipt()
        del value["candidate_patch_sha256"]
        value.update(runtime_kind=fixture.FRESH_KIND,
                     candidate_patch_sha256s=list(fixture.PROTOCOL_HISTORY_PATCHES))
        fixture.validate_receipt(value)
        for pins in (["b"*64]*4, list(reversed(fixture.PROTOCOL_HISTORY_PATCHES)),
                     fixture.PROTOCOL_HISTORY_PATCHES+["c"*64]):
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                fixture.validate_receipt({**value,"candidate_patch_sha256s":pins})

    def test_protocol_history_runtime_identity_requires_its_distinct_chain(self):
        chain = {"upstream_commit":"a"*40,"patch_sha256":list(fixture.PROTOCOL_HISTORY_PATCHES)}
        with self.assertRaises(ValueError):
            fixture.runtime_identity({"kind":fixture.FRESH_KIND,"chain":chain},"fresh")
        chain["native_protocol_history"] = {
            "protocol":{"kind":"omux-protocol-history-native-checks-v1","stage":1},
            "schema":{"kind":"omux-protocol-history-native-checks-v1","stage":2},
            "cli":{"kind":"omux-protocol-history-cli-qualification-v1"},
            "artifact_envelopes":{},"artifact_files":{}}
        self.assertEqual(fixture.runtime_identity({"kind":fixture.FRESH_KIND,"chain":chain},"fresh")
                         ["candidate_patch_sha256s"],fixture.PROTOCOL_HISTORY_PATCHES)
        chain["native_protocol_history"]["protocol"]["stage"] = True
        with self.assertRaises(ValueError):
            fixture.runtime_identity({"kind":fixture.FRESH_KIND,"chain":chain},"fresh")

    def test_runtime_selection_preserves_default_and_refuses_implicit_or_duplicate_fresh_kind(self):
        self.assertEqual(fixture.runtime_arguments(["bundle", "candidate", "receipt"]),
                         ("retained", None, ["bundle", "candidate", "receipt"]))
        with mock.patch.object(Path, "resolve", lambda self, **kwargs: self):
            kind, pin, arguments = fixture.runtime_arguments([
                "--runtime-kind=fresh", "--runtime-pin=/public/input-pin.json", "bundle"])
            self.assertEqual((kind, pin, arguments), ("fresh", Path("/public/input-pin.json"), ["bundle"]))
        for args in (["--runtime-kind=fresh"], ["--runtime-pin=/public/input-pin.json"],
                     ["--runtime-kind=unknown"],
                     ["--runtime-kind=fresh", "--runtime-pin=/public/input-pin.json", "--runtime-kind=fresh"]):
            with self.subTest(arguments=args), self.assertRaises(ValueError):
                fixture.runtime_arguments(args)

    def test_actual_tui_runtime_reader_defaults_to_retained_and_live_reader_is_explicit(self):
        class VerifiedStop(Exception):
            pass
        selected = mock.Mock(return_value=({}, {}))
        with mock.patch.dict(fixture.tui.os.environ, {"OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}), \
             mock.patch.object(fixture.support.runtime_package, "read_runtime_bundle", return_value=({}, {})) as retained, \
             mock.patch.object(Path, "mkdir", side_effect=VerifiedStop):
            with self.assertRaises(VerifiedStop):
                fixture.tui.inside(Path("bundle"), Path("candidate"), Path("receipt"), Path("keyring"), Path("root"))
            retained.assert_called_once_with(Path("candidate"), Path("receipt"))
            retained.reset_mock()
            with self.assertRaises(VerifiedStop):
                fixture.tui.inside(Path("bundle"), Path("candidate"), Path("receipt"), Path("keyring"), Path("root"),
                                   live=mock.Mock(read_runtime_bundle=selected))
            selected.assert_called_once_with(Path("candidate"), Path("receipt"))
            retained.assert_not_called()

    def test_fresh_adapter_checks_independent_input_pins_before_verifier_and_manifest_identity_after(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            root = Path(temporary)
            candidate, metadata, pin_path = (root / name for name in ("archive", "receipt.json", "input-pin.json"))
            payload = b"generated nonsecret archive transport model"
            document = {"kind": fixture.FRESH_KIND}
            manifest = {"kind": fixture.FRESH_KIND, "files": {}, "chain": {
                "upstream_commit": "a" * 40, "patch_sha256": ["b" * 64, "c" * 64, "d" * 64]}}
            raw_receipt = json.dumps(document).encode()
            raw_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
            pin = {"kind": fixture.FRESH_KIND}
            for role, raw in (("archive", payload), ("receipt", raw_receipt), ("manifest", raw_manifest)):
                pin[role + "_sha256"] = hashlib.sha256(raw).hexdigest()
                pin[role + "_bytes"] = len(raw)
            for path, raw in ((candidate, payload), (metadata, raw_receipt)):
                path.write_bytes(raw)
                path.chmod(0o600)
            def write_pin(value):
                pin_path.write_text(json.dumps(value))
                pin_path.chmod(0o600)
            write_pin(pin)
            verifier = mock.Mock(return_value=(manifest, {}))
            self.assertEqual(fixture.fresh_runtime_bundle(candidate, metadata, pin_path, verifier), (manifest, {}))
            verifier.assert_called_once_with(payload, document)
            for role in ("archive", "receipt"):
                verifier.reset_mock()
                write_pin({**pin, role + "_sha256": "0" * 64})
                with self.subTest(role=role), self.assertRaises(ValueError):
                    fixture.fresh_runtime_bundle(candidate, metadata, pin_path, verifier)
                verifier.assert_not_called()
            write_pin({**pin, "manifest_sha256": "0" * 64})
            with self.assertRaises(ValueError):
                fixture.fresh_runtime_bundle(candidate, metadata, pin_path, verifier)
            write_pin({**pin, "archive_bytes": True})
            with self.assertRaises(ValueError):
                fixture.fresh_runtime_bundle(candidate, metadata, pin_path, verifier)
            with self.assertRaises(ValueError):
                fixture.fresh_runtime_bundle(candidate, metadata, None, verifier)

    def test_fresh_identity_reads_actual_chain_and_retained_identity_stays_candidate_bound(self):
        chain = {"upstream_commit": "a" * 40, "patch_sha256": ["b" * 64, "c" * 64, "d" * 64]}
        self.assertEqual(fixture.runtime_identity({"kind": fixture.FRESH_KIND, "chain": chain}, "fresh"),
                         {"runtime_kind": fixture.FRESH_KIND, "upstream_commit": chain["upstream_commit"],
                          "candidate_patch_sha256s": chain["patch_sha256"]})
        self.assertEqual(fixture.runtime_identity({"candidate": {"upstream_commit": "a" * 40,
                                                                 "patch_sha256": "b" * 64}}, "retained"),
                         {"upstream_commit": "a" * 40, "candidate_patch_sha256": "b" * 64})

    def test_receipt_rejects_broader_claims(self):
        for field in ("accepted_history_cold_resume_proven", "provider_rejection_handoff_proven",
                      "concurrent_handoff_proven", "full_native_account_lifecycle_proven",
                      "native_detach_proven", "integration_restoration_proven"):
            value = receipt()
            value[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_receipt_rejects_extra_private_fields_and_raw_identifiers(self):
        for key in ("access_token", "account_id", "thread_id", "source_path", "diagnostics"):
            value = receipt()
            value[key] = "fixture-private-field"
            with self.subTest(field=key), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_receipt_rejects_replay_tools_and_integer_booleans(self):
        for key, replacement in (("tool_calls", 1), ("accepted_work_repeated", True),
                                 ("same_process", 1), ("submitted_turns", 3)):
            value = receipt()
            value[key] = replacement
            with self.subTest(field=key), self.assertRaises(ValueError):
                fixture.validate_receipt(value)

    def test_supported_minimum_effort_is_catalog_bound(self):
        catalog = {"models": [{"slug": "fixture-model", "input_modalities": ["text"],
                              "supported_reasoning_levels": [{"effort": "medium"}, {"effort": "low"}]}]}
        self.assertEqual("low", fixture.minimum_reasoning_effort(catalog, "fixture-model"))
        with self.assertRaises(ValueError):
            fixture.minimum_reasoning_effort(catalog, "fixture-missing")
        catalog["models"][0]["supported_reasoning_levels"] = []
        with self.assertRaises(ValueError):
            fixture.minimum_reasoning_effort(catalog, "fixture-model")

    def test_readable_reasoning_is_outside_text_policy(self):
        for body in ({"type": "reasoning", "summary": [{"type": "summary_text", "text": "fixture"}]},
                     {"type": "reasoning", "summary": [], "content": [{"type": "reasoning_text", "text": "fixture"}]}):
            events = completed_events()
            events.insert(1, {"type": "response_item", "payload": body})
            with self.subTest(body=body), self.assertRaises(ValueError):
                self.complete(events)
        events = completed_events()
        events.insert(1, {"type": "response_item", "payload": {"type": "reasoning", "summary": [], "content": None}})
        self.assertTrue(self.complete(events))

    def test_completed_text_requires_actual_completion_and_usage_record(self):
        self.assertTrue(self.complete(completed_events()))
        self.assertFalse(self.complete(completed_events()[:-1]))
        self.assertFalse(self.complete([item for item in completed_events()
                                        if item["type"] != "token_usage_record"]))

    def test_task_complete_error_cannot_prove_success(self):
        events = completed_events()
        events[-1]["payload"]["error"] = {"message": "fixture failure"}
        self.assertFalse(self.complete(events))

    def test_tool_record_and_nontext_input_fail_closed(self):
        for payload in ({"type": "function_call"}, {"type": "message", "role": "user",
                       "content": [{"type": "input_image", "image_url": "fixture"}]}):
            events = completed_events()
            events.insert(1, {"type": "response_item", "payload": payload})
            with self.subTest(kind=payload["type"]), self.assertRaises(ValueError):
                self.complete(events)

    def test_repeated_accepted_text_and_wrong_final_text_are_not_completion(self):
        events = completed_events()
        events.insert(1, copy.deepcopy(events[1]))
        self.assertFalse(self.complete(events))
        events = completed_events()
        events[1]["payload"]["content"][0]["text"] = "fixture unexpected output"
        self.assertFalse(self.complete(events))

if __name__ == "__main__":
    unittest.main()
