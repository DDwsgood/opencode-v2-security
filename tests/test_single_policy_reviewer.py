"""Focused contract tests for the single ("LOOSE") legacy reviewer policy.

The strict "HARD" policy was removed from the legacy reviewers. These tests
pin the resulting contract: "HARD" is rejected explicitly (never selected,
defaulted, or silently converted), the LOOSE parse no longer requires a
`bypassing` field, and malformed reviewer output is still a protocol failure.
They deliberately do NOT re-assert any removed HARD behaviour.
"""

from __future__ import annotations

import importlib.util
import io
import os
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

JEV_SCRIPT = Path(__file__).parents[1] / "src" / "security" / "jev-reviewer.py"
JEV_SPEC = importlib.util.spec_from_file_location("jev_single_policy_under_test", JEV_SCRIPT)
assert JEV_SPEC is not None and JEV_SPEC.loader is not None
jev = importlib.util.module_from_spec(JEV_SPEC)
JEV_SPEC.loader.exec_module(jev)


def _valid_head_answers() -> dict:
    """A fully valid answers object for the head question set, WITHOUT any
    `bypassing` answer — the LOOSE contract must not require one."""
    answers: dict = {}
    for name, question in jev.build_questions({}).items():
        if name == "bypassing" or not isinstance(question, dict):
            continue
        qtype = question.get("type")
        if qtype == "noul":
            answers[name] = {"type": "noul", "noul": 0.0}
        else:
            criteria = question.get("criteria")
            labels = list(criteria) if isinstance(criteria, dict) else []
            answers[name] = {"type": qtype, "choice": labels[0] if labels else "allow"}
    return answers


class JevSinglePolicyTests(unittest.TestCase):
    def test_main_rejects_hard_policy(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {jev.ENV_POLICY: "HARD"}):
            with redirect_stderr(stderr):
                rc = jev.main()
        self.assertEqual(rc, jev.EXIT_PROTOCOL)
        self.assertIn("removed", stderr.getvalue())

    def test_main_rejects_unknown_policy(self):
        stderr = io.StringIO()
        with patch.dict(os.environ, {jev.ENV_POLICY: "STRICT"}):
            with redirect_stderr(stderr):
                rc = jev.main()
        self.assertEqual(rc, jev.EXIT_PROTOCOL)

    def test_hard_inspection_helper_is_gone(self):
        self.assertFalse(hasattr(jev, "_hard_script_inspection_missing"))

    def test_loose_answers_do_not_require_bypassing(self):
        answers = _valid_head_answers()
        self.assertNotIn("bypassing", answers)
        # Must not raise: bypassing is output-only and carries no deny rule.
        self.assertIs(jev._validate_answers(answers, jev.build_questions({})), answers)

    def test_malformed_bypassing_answer_is_tolerated(self):
        answers = _valid_head_answers()
        answers["bypassing"] = {"type": "noul", "noul": 1.5}
        jev._validate_answers(answers, jev.build_questions({}))

    def test_missing_safety_critical_answer_is_a_protocol_failure(self):
        answers = _valid_head_answers()
        answers.pop("decision")
        with self.assertRaises(jev.JevProtocolError):
            jev._validate_answers(answers, jev.build_questions({}))


if __name__ == "__main__":
    unittest.main()
