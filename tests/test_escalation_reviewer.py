from __future__ import annotations

import importlib.util
import io
import json
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).parents[1] / "src" / "security" / "escalation-reviewer.py"
SPEC = importlib.util.spec_from_file_location("escalation_reviewer_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reviewer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reviewer)


def sample_request() -> dict:
    return {
        "command": "sudo apt-get install curl",
        "categories": ["privilege", "host", "sandbox"],
        "justification": "install the missing dependency",
        "currentUserInput": "Test the service at https://example.test",
        "recentContext": [
            {"role": "user", "text": "Please test the service."},
            {"role": "assistant", "text": "curl is missing."},
        ],
        "permScope": {"r": True, "w": True, "x": True},
        "previousFailedEscalations": [
            {
                "command": "sudo apt-get install curl",
                "categories": ["privilege", "host"],
                "justification": "first attempt",
                "decision": "deny",
            }
        ],
    }


class PayloadHandler(BaseHTTPRequestHandler):
    payload: dict | None = None
    auth: str | None = None
    user_agent: str | None = None

    def do_POST(self) -> None:  # noqa: N802
        self.__class__.payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.__class__.auth = self.headers.get("Authorization")
        self.__class__.user_agent = self.headers.get("User-Agent")
        response = json.dumps(
            {"choices": [{"message": {"content": "<think>internal</think>allow_once"}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class EscalationReviewerTests(unittest.TestCase):
    def test_schema_rejects_duplicate_extra_wildcard_and_large_context(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            reviewer.parse_json_strict('{"command":"x","command":"y"}')

        extra = sample_request()
        extra["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unexpected"):
            reviewer.validate_request(extra)

        for category in ("all", "ALL", "*", "All"):
            bad = sample_request()
            bad["categories"] = [category]
            with self.assertRaisesRegex(ValueError, "forbidden"):
                reviewer.validate_request(bad)

        unknown = sample_request()
        unknown["categories"] = ["os"]
        # Unknown category names no longer fail schema validation; the
        # deterministic gate routes them to the user before the model runs.
        reviewer.validate_request(unknown)

        # Every whitelisted category validates, including the new `privilege`.
        for category in reviewer.ALLOWED_CATEGORIES:
            ok = sample_request()
            ok["categories"] = [category]
            reviewer.validate_request(ok)
        self.assertIn("privilege", reviewer.ALLOWED_CATEGORIES)

        too_many = sample_request()
        too_many["recentContext"] = [
            {"role": "user", "text": "x"} for _ in range(reviewer.MAX_CONTEXT_MESSAGES + 1)
        ]
        with self.assertRaisesRegex(ValueError, "too many"):
            reviewer.validate_request(too_many)

    def test_prompt_contains_goal_and_marks_all_text_as_untrusted(self) -> None:
        system, prompt = reviewer.build_prompt(sample_request())
        self.assertIn("untrusted", system.lower())
        self.assertIn("safety floors", system)
        self.assertIn("Test the service", prompt)
        self.assertIn("sudo apt-get install curl", prompt)
        self.assertIn("[untrusted data]", prompt)
        self.assertIn("[untrusted data: command issued by the agent]", prompt)
        self.assertNotIn("[untrusted user data]", prompt)
        self.assertIn("Explicit current user input", prompt)
        # The reviewed command is agent-issued, not user-typed.
        self.assertIn(
            "Requested command:\n\n<data>\n[untrusted data: command issued by the agent]\nsudo apt-get install curl\n</data>",
            prompt,
        )
        # System prompt: aligned floor, allow_once ceiling, failed-decision scope.
        self.assertIn("never raises the session's read/write/execute permission ceiling", system)
        self.assertIn("permScope.w is false, return deny", system)
        self.assertIn("previousFailedEscalations lists only collect_evidence and deny outcomes", system)
        self.assertIn("reasonable task-related work, including implied steps", system)
        self.assertIn("last five user messages", system)
        self.assertNotIn("literal shell escape", system)
        self.assertNotIn("explicit user request", system)
        self.assertIn("first attempt", prompt)
        self.assertIn("role=user", prompt)

    def test_payload_is_thinking_enabled_without_temperature_or_json_mode(self) -> None:
        payload = reviewer.build_payload(sample_request(), "test-model")
        # Thinking/reasoning models commonly reject these two knobs, so the
        # escalation payload must not send either of them.
        self.assertNotIn("temperature", payload)
        self.assertNotIn("response_format", payload)
        self.assertEqual(payload["chat_template_kwargs"], {"enable_thinking": True})
        self.assertEqual(payload["max_tokens"], 4096)
        self.assertEqual(payload["stream"], False)
        self.assertEqual(payload["model"], "test-model")
        self.assertEqual([message["role"] for message in payload["messages"]], ["system", "user"])
        # Keep the wire payload minimal: no accidental provider-specific extras.
        self.assertEqual(
            set(payload),
            {"model", "messages", "max_tokens", "stream", "chat_template_kwargs"},
        )
        # The system prompt must demand exactly one plain decision word, never JSON.
        self.assertIn("Return exactly one final assistant content word", payload["messages"][0]["content"])

    def test_decision_parser_is_strict(self) -> None:
        self.assertEqual(reviewer.parse_decision("allow_once"), "allow_once")
        self.assertEqual(reviewer.parse_decision("collect_evidence"), "collect_evidence")
        # The legacy ask_user word normalizes to the unattended evidence
        # route instead of failing the review.
        self.assertEqual(reviewer.parse_decision("ask_user"), "collect_evidence")
        self.assertEqual(
            reviewer.parse_decision("<think>reason</think>\nask_user"),
            "collect_evidence",
        )
        self.assertEqual(reviewer.parse_decision(" <think>reason</think>\n deny "), "deny")
        for content in (
            "allow_once because",
            "```deny```",
            "allow_once deny",
            "<think>one</think><think>two</think>deny",
            "<thinking>reason</thinking>deny",
            "unknown",
        ):
            with self.assertRaises(ValueError):
                reviewer.parse_decision(content)

    def test_openai_payload_headers_and_chat_path(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), PayloadHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            review = reviewer.validate_request(sample_request())
            payload = reviewer.build_payload(review, "test-model")
            content = reviewer.post_chat(
                payload,
                f"http://127.0.0.1:{server.server_port}/v1",
                "secret-test-key",
            )
            self.assertEqual(content, "<think>internal</think>allow_once")
            self.assertEqual(PayloadHandler.auth, "Bearer secret-test-key")
            self.assertEqual(PayloadHandler.user_agent, reviewer.USER_AGENT)
            self.assertIsNotNone(PayloadHandler.payload)
            assert PayloadHandler.payload is not None
            self.assertNotIn("response_format", PayloadHandler.payload)
            self.assertNotIn("temperature", PayloadHandler.payload)
            self.assertEqual(
                PayloadHandler.payload["chat_template_kwargs"], {"enable_thinking": True}
            )
            self.assertEqual(PayloadHandler.payload["max_tokens"], 4096)
        finally:
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()


class PreviousDenialSchemaTests(unittest.TestCase):
    def test_previous_denial_validates_and_attaches(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": ["secret", "filesystem"]}
        review = reviewer.validate_request(req)
        self.assertEqual(
            review["previousDenial"],
            {"command": req["command"], "riskCategories": ["secret", "filesystem"]},
        )

    def test_previous_denial_rejects_bad_shapes_and_names(self) -> None:
        for bad in (
            {"command": "x"},
            {"command": "x", "riskCategories": ["secret"], "extra": 1},
            {"command": "x", "riskCategories": "secret"},
            {"command": "x", "riskCategories": ["os"]},
            {"command": "x", "riskCategories": ["dynamic"]},
            {"command": "x", "riskCategories": ["secret", "secret"]},
        ):
            req = sample_request()
            req["previousDenial"] = bad
            with self.assertRaisesRegex(ValueError, "previousDenial"):
                reviewer.validate_request(req)

    def test_previous_denial_empty_risk_categories_never_trip_the_gate(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": []}
        review = reviewer.validate_request(req)
        self.assertFalse(reviewer.coverage_missing(review))


class DeterministicGateTests(unittest.TestCase):
    def test_dynamic_and_slow_are_mechanism_tampering(self) -> None:
        for name in ("dynamic", "slow"):
            req = sample_request()
            req["categories"] = [name]
            review = reviewer.validate_request(req)
            self.assertEqual(reviewer.deterministic_decision(review), "deny")

    def test_unknown_names_deny(self) -> None:
        # No human can resolve an unknown name: the request is defective and
        # denied deterministically before the model is consulted.
        req = sample_request()
        req["categories"] = ["os", "secret"]
        review = reviewer.validate_request(req)
        self.assertEqual(reviewer.deterministic_decision(review), "deny")

    def test_canonical_and_sandbox_names_still_reach_the_model(self) -> None:
        # sandbox stays a grantable layer category; its justification is judged
        # by the model, not by the deterministic name gate.
        for categories in (["filesystem"], ["sandbox"], ["privilege", "host", "sandbox"]):
            req = sample_request()
            req["categories"] = categories
            review = reviewer.validate_request(req)
            self.assertIsNone(reviewer.deterministic_decision(review))

    def test_coverage_gate_requires_recorded_risk_covered(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": ["secret", "filesystem"]}
        review = reviewer.validate_request(req)
        self.assertTrue(reviewer.coverage_missing(review))
        self.assertEqual(reviewer.deterministic_decision(review), "collect_evidence")
        covered = sample_request()
        covered["categories"] = ["privilege", "host", "sandbox", "secret", "filesystem"]
        covered["previousDenial"] = {"command": covered["command"], "riskCategories": ["secret", "filesystem"]}
        review = reviewer.validate_request(covered)
        self.assertFalse(reviewer.coverage_missing(review))
        self.assertIsNone(reviewer.deterministic_decision(review))

    def test_coverage_gate_only_applies_to_the_same_command(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": "different command", "riskCategories": ["secret"]}
        review = reviewer.validate_request(req)
        self.assertFalse(reviewer.coverage_missing(review))

    def test_final_decision_downgrades_uncovered_allow_once(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": ["secret"]}
        review = reviewer.validate_request(req)
        self.assertEqual(reviewer.finalize_decision(review, "allow_once"), "collect_evidence")
        self.assertEqual(reviewer.finalize_decision(review, "deny"), "deny")
        self.assertEqual(reviewer.finalize_decision(review, "collect_evidence"), "collect_evidence")

    def test_main_skips_the_model_when_coverage_missing(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": ["secret"]}
        with (
            patch.object(reviewer, "_load_config", return_value=("http://127.0.0.1:1", "m", "k")),
            patch.object(
                reviewer,
                "_read_review_input",
                return_value=reviewer.read_review_input(json.dumps(req)),
            ),
            patch.object(reviewer, "post_chat", side_effect=AssertionError("the model must not be consulted")),
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(reviewer.main(), 0)
        lines = out.getvalue().strip().splitlines()
        self.assertEqual(lines[0], "collect_evidence")
        self.assertTrue(lines[1].startswith("detail:"))
        self.assertIn('"coverage_missing"', lines[1])

    def test_main_skips_the_model_for_mechanism_tampering(self) -> None:
        req = sample_request()
        req["categories"] = ["dynamic"]
        with (
            patch.object(reviewer, "_load_config", return_value=("http://127.0.0.1:1", "m", "k")),
            patch.object(
                reviewer,
                "_read_review_input",
                return_value=reviewer.read_review_input(json.dumps(req)),
            ),
            patch.object(reviewer, "post_chat", side_effect=AssertionError("the model must not be consulted")),
            redirect_stdout(io.StringIO()) as out,
        ):
            self.assertEqual(reviewer.main(), 0)
        lines = out.getvalue().strip().splitlines()
        self.assertEqual(lines[0], "deny")
        self.assertTrue(lines[1].startswith("detail:"))


class PromptContentTests(unittest.TestCase):
    def test_prompt_renders_previous_denial(self) -> None:
        req = sample_request()
        req["previousDenial"] = {"command": req["command"], "riskCategories": ["secret", "filesystem"]}
        _system, prompt = reviewer.build_prompt(req)
        self.assertIn("Previous denial recorded for this same command", prompt)
        self.assertIn('["secret","filesystem"]', prompt)

    def test_system_prompt_carries_coverage_write_vs_execute_and_disambiguation(self) -> None:
        system = reviewer.SYSTEM_PROMPT
        # Coverage rule.
        self.assertIn("requested categories to cover every riskCategory", system)
        self.assertIn("prefer collect_evidence over allow_once", system)
        # Write-vs-execute clause.
        self.assertIn("merely writing or printing fixtures", system)
        self.assertIn("command substitutions or subsequent execution", system)
        self.assertIn("executing a script later is a different command", system)
        # Disambiguation list: compact, defines exactly the canonical set, and
        # never teaches layer toggles as grantable families.
        lines = [line for line in system.splitlines() if line.startswith("- ")]
        self.assertLessEqual(len(lines), 12)
        defined = {line.split(":")[0].strip("- ").strip() for line in lines}
        self.assertEqual(defined, set(reviewer.ALLOWED_CATEGORIES))
        self.assertIn("never what is written", system)
        self.assertIn("dynamic, slow", system)


if __name__ == "__main__":
    unittest.main()
