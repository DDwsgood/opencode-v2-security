"""risk_heads projection + jev-reviewer integration regressions.

Covers the mandates the head-based upgrade must hold:
- footprint vs actor-context independence (the same footprint under an
  ordinary vs privileged_exec actor bills identical categories);
- a verbatim raw ALLOW is preserved even when an unselected branch carries
  p_deny=0.9 — rawDecision is never rewritten by the verdict;
- credential mode-hardening stays the credential class, not privilege;
- ordinary SSH/socat-style brokering does not bill privilege;
- unconfirmed data effects (unclear) bill nothing — they surface in
  needsEvidence instead;
- a native static floor reports decisionSource=native_floor while the
  model's verbatim raw decision stays intact — never re-aggregated into a
  fake model deny.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_SEC = Path(__file__).resolve().parents[1] / "src" / "security"
sys.path.insert(0, str(_SEC))
import risk_heads  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "jev_rh_under_test", _SEC / "jev-reviewer.py")
jev = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(jev)


def _head_answer(choice: str) -> dict:
    return {"type": "choice", "choice": choice}


def _neutral_answers(**overrides) -> dict:
    """All-neutral head answers; overrides is {head_name: choice}."""
    neutral = {"actor_context": "ordinary", "floor": "no"}
    answers = {}
    for name in risk_heads.HEAD_ORDER:
        answers[name] = _head_answer(neutral.get(name, "none"))
    for name, choice in overrides.items():
        answers[name] = _head_answer(choice)
    return answers


def _full_answers(**head_overrides) -> dict:
    """A valid jev-reviewer answer set with neutral judges."""
    answers = _neutral_answers(**head_overrides)
    answers.update({
        "decision": {"type": "choice", "choice": "allow",
                     "probabilities": {"allow": 1.0, "deny": 0.0}},
        "harm_score": {"type": "noul", "noul": 0},
        "secret_exposure": {"type": "noul", "noul": 0},
        "privilege_or_kernel": {"type": "noul", "noul": 0.0},
        "destructive": {"type": "noul", "noul": 0.0},
    })
    return answers


class ProjectionIndependenceTests(unittest.TestCase):
    def test_same_footprint_under_different_actor_context(self) -> None:
        # actor_context is a diagnostic tag — privileged_exec never bills a
        # category and never clears one either.
        for actor in ("ordinary", "privileged_exec", "unclear"):
            projection = risk_heads.project_heads(
                _neutral_answers(cat_data="local", actor_context=actor))
            self.assertEqual(projection["categories"], ["filesystem"], actor)
            self.assertEqual(projection["context"]["actor"], actor)
        # And an elevated actor alone bills nothing.
        projection = risk_heads.project_heads(
            _neutral_answers(actor_context="privileged_exec"))
        self.assertEqual(projection["categories"], [])

    def test_credential_mode_hardening_stays_credential_class(self) -> None:
        # chmod on a credential file is a credential effect (its own mode
        # weakening is excluded from the control class by the frozen
        # negative register) — billed secret, never privilege.
        projection = risk_heads.project_heads(
            _neutral_answers(cat_credential="in_place", cat_control="none"))
        self.assertEqual(projection["categories"], ["secret"])
        self.assertNotIn("privilege", projection["categories"])
        self.assertNotIn("host", projection["categories"])

    def test_brokering_bills_no_privilege(self) -> None:
        # Ordinary SSH/kubectl/socat traffic moving is explicitly not a
        # caller privilege boundary: no control effect, loopback or benign
        # publication — zero categories.
        for pub in ("loopback_only", "benign_public", "none"):
            projection = risk_heads.project_heads(
                _neutral_answers(cat_control="none",
                                 network_access_publication=pub))
            self.assertEqual(projection["categories"], [], pub)
        # A non-public publication is the network family, still not
        # privilege.
        projection = risk_heads.project_heads(
            _neutral_answers(network_access_publication="nonpublic_publication"))
        self.assertEqual(projection["categories"], ["network"])

    def test_unclear_never_bills_a_category(self) -> None:
        # Unconfirmed facts (unknown SQL target, unpinned scope) bill no
        # category — they surface in needsEvidence.
        projection = risk_heads.project_heads(
            _neutral_answers(cat_data="unclear", cat_communication="unclear"))
        self.assertEqual(projection["categories"], [])
        self.assertIn("cat_data", projection["needsEvidence"])
        self.assertIn("cat_communication", projection["needsEvidence"])

    def test_off_host_credential_bills_secret_and_network(self) -> None:
        projection = risk_heads.project_heads(
            _neutral_answers(cat_credential="off_host"))
        self.assertEqual(projection["categories"], ["network", "secret"])

    def test_probs_only_head_is_needs_evidence_not_a_category(self) -> None:
        # A strong probability map without a verbatim selected choice must
        # never promote a weak signal into a category.
        answers = _neutral_answers()
        answers["cat_data"] = {"type": "choice",
                               "probabilities": {"local": 0.95, "none": 0.05}}
        projection = risk_heads.project_heads(answers)
        self.assertEqual(projection["categories"], [])
        self.assertIn("cat_data", projection["needsEvidence"])


class ReviewerIntegrationTests(unittest.TestCase):
    def _review(self, answers: dict, command: str = "ls -la") -> dict:
        with patch.object(jev, "jev_call",
                          return_value={"answers": answers}) as call:
            result = jev.review_request(
                {"command": command}, "test-model", 1, "test-placeholder",
                jev.DEFAULT_THRESHOLDS)
        call.assert_called_once()
        return result

    def test_raw_allow_preserved_with_unselected_high_deny_probability(self):
        # The verbatim raw ALLOW stands even when the unselected deny branch
        # carries p=0.9 plus high specialist scores — scores are diagnostics
        # only and never veto the selected choice. This is the core
        # intent-misidentification regression.
        answers = _full_answers()
        answers["decision"] = {"type": "choice", "choice": "allow",
                               "probabilities": {"allow": 0.1, "deny": 0.9}}
        answers["harm_score"] = {"type": "noul", "noul": 1.0}
        answers["secret_exposure"] = {"type": "noul", "noul": 1.0}
        answers["privilege_or_kernel"] = {"type": "noul", "noul": 0.95}
        answers["destructive"] = {"type": "noul", "noul": 0.95}
        result = self._review(answers)
        self.assertFalse(result["deny"])   # verbatim allow stands
        raw = result["assessment"]["rawDecision"]
        self.assertEqual(raw["choice"], "allow")
        self.assertEqual(raw["p_deny"], 0.9)   # unselected mass still reported
        self.assertEqual(result["assessment"]["decisionSource"], "model_allow")
        self.assertEqual(result["verdict_detail"]["harm"], 1.0)

    def test_raw_deny_needs_no_score_corroboration(self) -> None:
        # The mirror image: a verbatim deny denies even with low p_deny and
        # zero specialist scores — no corroboration required either way.
        answers = _full_answers()
        answers["decision"] = {"type": "choice", "choice": "deny",
                               "probabilities": {"allow": 0.9, "deny": 0.1}}
        result = self._review(answers)
        self.assertTrue(result["deny"])
        self.assertEqual(result["verdict_detail"]["fired"], ["decision"])
        self.assertEqual(result["assessment"]["decisionSource"], "model_deny")
        self.assertEqual(result["assessment"]["rawDecision"]["choice"], "deny")

    def test_probabilities_only_answer_is_protocol_error_not_intent(self):
        # An answer without a selected choice cannot be interpreted — it is
        # a protocol failure (fail closed upstream), never a guessed vote.
        answers = _full_answers()
        answers["decision"] = {"type": "choice",
                               "probabilities": {"allow": 0.1, "deny": 0.9}}
        with self.assertRaises(jev.JevProtocolError):
            jev._validate_answers(answers, jev.build_questions({}))
        # And for the heads too: no legal label → protocol error.
        answers = _full_answers()
        answers["floor"] = {"type": "choice",
                            "probabilities": {"yes": 0.9, "no": 0.1}}
        with self.assertRaises(jev.JevProtocolError):
            jev._validate_answers(answers, jev.build_questions({}))

    def test_floor_no_with_unused_high_yes_probability_is_not_a_floor(self):
        # floor choice "no" must never become a floor verdict because of an
        # unselected p_yes — and it stays a clean allow here.
        answers = _full_answers()
        answers["floor"] = {"type": "choice", "choice": "no",
                            "probabilities": {"yes": 0.9, "no": 0.1}}
        result = self._review(answers)
        self.assertFalse(result["deny"])
        self.assertEqual(result["assessment"]["floor"], "no")
        self.assertEqual(result["assessment"]["decisionSource"], "model_allow")

    def test_allow_carries_footprint_and_assessment(self) -> None:
        result = self._review(_full_answers(cat_credential="in_place"))
        self.assertFalse(result["deny"])
        # The intrinsic footprint lives on the result AND the assessment;
        # the host's wire validator clears top-level categories on ALLOW —
        # assessment.categories is the durable carrier it consumes.
        self.assertEqual(result["categories"], ["secret"])
        assessment = result["assessment"]
        self.assertEqual(assessment["categories"], ["secret"])
        self.assertEqual(assessment["decisionSource"], "model_allow")
        self.assertEqual(assessment["policyVersion"], risk_heads.POLICY_VERSION)
        self.assertEqual(assessment["context"]["actor"], "ordinary")
        self.assertEqual(assessment["floor"], "no")
        self.assertEqual(raw_choice(assessment), "allow")

    def test_model_floor_head_denies_as_model_floor(self) -> None:
        result = self._review(_full_answers(floor="yes"))
        self.assertTrue(result["deny"])
        self.assertEqual(result["verdict_detail"]["fired"], ["floor"])
        self.assertEqual(result["assessment"]["decisionSource"], "model_floor")
        self.assertEqual(result["assessment"]["floor"], "yes")

    def test_unclear_floor_is_evidence_not_a_denial(self) -> None:
        result = self._review(_full_answers(floor="unclear"))
        self.assertFalse(result["deny"])
        self.assertIn("floor", result["assessment"]["needsEvidence"])

    def test_native_floor_cannot_be_rewritten_as_model_deny(self) -> None:
        # rm -rf / hits the static floor guard while the model said allow —
        # the source names the native layer, rawDecision stays verbatim.
        result = self._review(_full_answers(), command="rm -rf /")
        self.assertTrue(result["deny"])
        self.assertEqual(result["verdict_detail"]["fired"], ["hard_guard"])
        self.assertEqual(result["assessment"]["decisionSource"], "native_floor")
        self.assertEqual(result["assessment"]["rawDecision"]["choice"], "allow")

    def test_liftable_guard_hit_is_native_static(self) -> None:
        # A category-owned guard hit that no grant covered reports
        # native_static — distinct from the unconditional floor.
        result = self._review(_full_answers(), command="git clean -fdx")
        self.assertTrue(result["deny"])
        self.assertEqual(result["assessment"]["decisionSource"],
                         "native_static")


def raw_choice(assessment: dict):
    return assessment["rawDecision"]["choice"]


if __name__ == "__main__":
    unittest.main()
