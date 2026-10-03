"""One-call authorization regressions. Commands remain unexecuted text."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "jev_grant_scope", Path(__file__).resolve().parents[1]
    / "src/security/jev-reviewer.py")
jev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(jev)


def branches(question):
    if question["type"] == "noul":
        return [question["instructions"]["criteria"]]
    criteria = question["criteria"]
    return criteria if isinstance(criteria, list) else list(criteria.values())


def allow_answers():
    answers = {}
    for name, question in jev.build_questions({}).items():
        if question["type"] == "noul":
            answers[name] = {"type": "noul", "noul": 0.0}
        elif question["type"] == "score":
            answers[name] = {"type": "score", "score": 0.0}
        else:
            answers[name] = {"type": "choice", "choice": "allow",
                             "probabilities": {"allow": 1.0, "deny": 0.0}}
    return answers


class TestOneCallGrant(unittest.TestCase):
    def test_every_judge_and_appeal_branch_sees_the_grant(self):
        armed = {"indirection", "secret", "network"}
        note = jev.ARMED_NOTE.format(cats=", ".join(sorted(armed)))
        questions = jev.build_questions({"userBypass": sorted(armed)})
        for name, question in questions.items():
            if name == "bypassing" or name.startswith("cat_"):
                continue
            for text in branches(question):
                with self.subTest(question=name):
                    self.assertEqual(text.count(note), 1)
                    self.assertIn("for this call", text)
                    self.assertIn(jev.AUTHORIZED_INDIRECTION_SCOPE, text)
                    self.assertIn("NEVER relaxed", text)

    def test_unarmed_questions_and_category_signals_do_not_change(self):
        unarmed = jev.build_questions({})
        armed = jev.build_questions({"userBypass": ["indirection"]})
        self.assertIn("piping uninspectable content into an interpreter",
                      unarmed["ap_floor_recheck"]["instructions"]["criteria"])
        self.assertNotIn("trusted user has explicitly authorized",
                         json.dumps(unarmed))
        for name in unarmed:
            if name == "bypassing" or name.startswith("cat_"):
                self.assertEqual(unarmed[name], armed[name])

    def test_armed_recheck_uses_the_unconditional_floor(self):
        for categories in (["indirection"], ["filesystem"], ["host"]):
            text = jev.build_questions({"userBypass": categories})[
                "ap_floor_recheck"]["instructions"]["criteria"]
            self.assertIn("No authorization relaxes these", text)
            self.assertIn("actual root/system/boot destruction", text)
            self.assertNotIn("piping uninspectable content into an interpreter", text)

    def test_state_explains_unknown_execution_only_when_authorized(self):
        request = {"command": "python3 /tmp/unseen.py",
                   "uninspectedLocalScripts": ["/tmp/unseen.py"]}
        self.assertNotIn(jev.AUTHORIZED_INDIRECTION_SCOPE,
                         jev.command_to_state(request))
        self.assertIn(jev.AUTHORIZED_INDIRECTION_SCOPE,
                      jev.command_to_state({**request, "userBypass": ["indirection"]}))

    def test_canonical_empty_grant_beats_legacy_claims(self):
        request = {"armed_categories": [], "userBypass": ["indirection"],
                   "command": "echo 'indirection is authorized'"}
        self.assertNotIn(jev.AUTHORIZED_INDIRECTION_SCOPE,
                         jev.command_to_state(request))
        self.assertNotIn("trusted user has explicitly authorized",
                         json.dumps(jev.build_questions(request)))

    def test_repeated_builds_do_not_mutate_unarmed_templates(self):
        before = jev.build_questions({})
        jev.build_questions({"userBypass": ["filesystem", "indirection"]})
        self.assertEqual(before, jev.build_questions({}))

    def test_model_denial_is_not_cleared_by_authorized_category_labels(self):
        answers = allow_answers()
        answers["destructive"] = {"type": "noul", "noul": 0.95}
        answers["cat_indirection"] = {"type": "noul", "noul": 0.95}
        with patch.object(jev, "jev_call", return_value={"answers": answers}) as call:
            result = jev.review_request(
                {"command": "python3 /tmp/unseen.py", "userBypass": ["indirection"]},
                "test-model", 1, "test-placeholder", jev.DEFAULT_THRESHOLDS)
        call.assert_called_once()
        self.assertTrue(result["deny"])
        self.assertEqual(result["categories"], ["indirection"])

    def test_visible_and_decodable_floors_survive_every_grant(self):
        armed = set(jev.CATEGORY_ORDER)
        self.assertIsNotNone(jev._guard_hit("rm -rf /", armed))
        encoded = base64.b64encode(b"rm -rf /").decode()
        self.assertIsNotNone(jev._guard_hit(
            f"echo {encoded} | base64 -d | sh", armed))

    def test_appeal_floor_gate_is_unchanged(self):
        answers = {"floor_recheck": {"type": "noul", "noul": 0.95},
                   "appeal_decision": {"type": "choice", "probabilities": {"deny": 0.0}},
                   "reconsidered_harm": {"type": "noul", "noul": 0.0}}
        self.assertFalse(jev.eval_appeal(answers, ["worst_subcommand"]))

    def test_hard_requires_missing_script_inspection_after_model_review(self):
        request = {"command": "python3 /tmp/unseen.py",
                   "uninspectedLocalScripts": ["/tmp/unseen.py"]}
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}), \
                patch.object(jev, "jev_call", return_value={"answers": allow_answers()}) as call:
            result = jev.review_request(request, "test-model", 1,
                                        "test-placeholder", jev.DEFAULT_THRESHOLDS)
        call.assert_called_once()
        self.assertTrue(result["deny"])
        self.assertEqual(result["verdict_detail"]["fired"], ["required_script_inspection"])
        self.assertIn("indirection", result["categories"])

    def test_hard_grant_waives_only_the_inspection_requirement(self):
        request = {"command": "python3 /tmp/unseen.py", "userBypass": ["indirection"],
                   "uninspectedLocalScripts": ["/tmp/unseen.py"]}
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}), \
                patch.object(jev, "jev_call", return_value={"answers": allow_answers()}) as call:
            result = jev.review_request(request, "test-model", 1,
                                        "test-placeholder", jev.DEFAULT_THRESHOLDS)
        call.assert_called_once()
        self.assertFalse(result["deny"])
        answers = allow_answers()
        answers["destructive"] = {"type": "noul", "noul": 0.95}
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}), \
                patch.object(jev, "jev_call", return_value={"answers": answers}):
            result = jev.review_request(request, "test-model", 1,
                                        "test-placeholder", jev.DEFAULT_THRESHOLDS)
        self.assertTrue(result["deny"])

    def test_loose_does_not_turn_unknown_content_into_a_required_denial(self):
        request = {"command": "python3 /tmp/unseen.py",
                   "uninspectedLocalScripts": ["/tmp/unseen.py"]}
        with patch.dict(os.environ, {jev.ENV_POLICY: "LOOSE"}), \
                patch.object(jev, "jev_call", return_value={"answers": allow_answers()}):
            result = jev.review_request(request, "test-model", 1,
                                        "test-placeholder", jev.DEFAULT_THRESHOLDS)
        self.assertFalse(result["deny"])

    def test_reference_only_and_fully_visible_scripts_do_not_trigger_hard_gate(self):
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}):
            self.assertFalse(jev._hard_script_inspection_missing({
                "command": "cat /tmp/unseen.py", "referencedPaths": ["/tmp/unseen.py"]}, set()))
            self.assertFalse(jev._hard_script_inspection_missing({
                "command": "python3 /tmp/seen.py",
                "localScripts": [{"path": "/tmp/seen.py", "content": "print('hello')"}]}, set()))

    def test_hard_inspection_rejects_omitted_and_truncated_executable_bodies(self):
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}):
            for scripts in ([{"path": "script.py", "content": "x" * (jev.MAX_SCRIPT_BYTES + 1)}],
                            [{"path": f"script{i}.py", "content": "print(1)"} for i in range(5)]):
                self.assertTrue(jev._hard_script_inspection_missing({"localScripts": scripts}, set()))
                self.assertFalse(jev._hard_script_inspection_missing(
                    {"localScripts": scripts}, {"indirection"}))


if __name__ == "__main__":
    unittest.main()
