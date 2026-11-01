"""Never turn the 16 real model scores into a false generalization pass."""
import json
import math
import struct
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class RealCounterfactualEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3d-2026-11-01.json").read_text())

    def test_genuine_loaded_score_run_and_failed_reversals_are_pinned(self):
        e=self.e
        self.assertEqual(e["verified_workflow_url"],
                         "https://github.com/Iniwura/falsum/actions/runs/41308317723")
        self.assertEqual(e["ci_artifact_id"],13084072990)
        self.assertEqual(e["diagnostic"]["total_real_model_inference_calls"],16)
        self.assertTrue(e["diagnostic"]["repeat_score_bits_identical"])
        self.assertEqual(e["diagnostic"]["reversal_families"],0)
        self.assertEqual(e["diagnostic"]["context_preferences_matching_provisional_rule"],2)
        self.assertEqual(e["diagnostic"]["families_with_both_preferences_correct"],0)
        self.assertEqual(e["diagnostic"]["ci_conclusion"],"success")

    def test_all_original_actual_f32_bits_match_claimed_scores(self):
        e=self.e
        cases=e["tested_cases"]
        self.assertEqual(len(cases),4)
        for r in cases:
            for typ in ("a","b"):
                bits=int(r["candidate_"+typ+"_f32_bits"],16)
                real=struct.unpack(">f",bits.to_bytes(4,"big"))[0]
                self.assertTrue(math.isfinite(real))
                self.assertEqual(real,r["candidate_"+typ+"_score"])
            a,b=r["candidate_a_score"],r["candidate_b_score"]
            self.assertEqual(a-b,r["margin_a_minus_b"])
            self.assertEqual(r["model_prefers"],r["candidate_a"])
            self.assertEqual(r["model_prefers"]==r["provisional_rule_expectation"],
                             r["matches_rule"])
        self.assertEqual(sum(x["matches_rule"] for x in cases),2)

    def test_release_status_remains_blocked_without_expert_data(self):
        e=self.e["release_decision"]
        self.assertFalse(e["checkpoint_acceptable_as_competitive_security_evaluator"])
        self.assertFalse(e["model_accuracy_established"])
        self.assertFalse(e["blind_holdout_tested"])
        self.assertFalse(e["registered_evaluator"])
        self.assertFalse(e["network_eligible"])
        self.assertEqual(e["independent_expert_labels"],0)
        self.assertEqual(e["submittable_training_rows"],0)
        self.assertEqual(e["release_recommendation"],
                         "BLOCK_MODEL_RELEASE_AND_REGISTRATION_PENDING_QUALITY_REMEDIATION")


if __name__=="__main__":
    unittest.main()
