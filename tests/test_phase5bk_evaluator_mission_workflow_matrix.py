"""Adversarial tests for the Evaluators mission/workflow evidence matrix."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest

from falsum import phase5bk_evaluator_mission_workflow_matrix as m


class EvaluatorMissionMatrixContract(unittest.TestCase):
    def test_two_official_security_review_mission_workflows_have_repeatable_tests(self):
        report = m.matrix()
        self.assertEqual(report["aggregate"]["distinct_official_missions_with_repeatable_supporting_tests"], 2)
        self.assertEqual([row["official_mission"] for row in report["mission_rows"]], [
            "Model Economy", "Web3 Native and DeFi",
        ])
        for row in report["mission_rows"]:
            self.assertGreaterEqual(len(row["repeatable_supporting_tests"]), 2)
            self.assertEqual(row["workflow_status"], "REPEATABLE_SUPPORTING_TEST")

    def test_authoritative_family_mapping_is_separate_from_acceptance(self):
        report = m.matrix()
        self.assertEqual(report["current_official_intent"], "SECURITY_REVIEW")
        self.assertEqual(report["historical_material_intent"], "SECURITY_REVIEW_GENERAL")
        self.assertTrue(report["intent_alias_or_protocol_compatibility_verified"])
        self.assertFalse(report["maintainer_acceptance_verified"])
        self.assertFalse(report["registered_evaluator_adapter_verified"])

    def test_supporting_tests_cannot_be_promoted_to_delivery_or_adoption(self):
        forged = deepcopy(m.matrix())
        forged["mission_rows"][0]["mission_completed"] = True
        with self.assertRaises(m.MatrixError):
            m.validate(forged)

        forged = deepcopy(m.matrix())
        forged["maintainer_acceptance_verified"] = True
        with self.assertRaises(m.MatrixError):
            m.validate(forged)
        forged = deepcopy(m.matrix())
        forged["aggregate"]["independent_application_consumption_verified"] = True
        with self.assertRaises(m.MatrixError):
            m.validate(forged)

    def test_matrix_is_public_safe_and_does_not_claim_ranking_change(self):
        raw = json.dumps(m.matrix(), sort_keys=True)
        self.assertNotIn("payment", raw.lower())
        self.assertNotIn("receipt", raw.lower())
        self.assertNotIn("private", raw.lower())
        self.assertFalse(m.matrix()["aggregate"]["ranking_change_claimed"])


if __name__ == "__main__":
    unittest.main()
