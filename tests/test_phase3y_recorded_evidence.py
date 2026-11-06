"""Check immutable, genuinely executed Phase 3Y research result (not mock model inference)."""
import copy
import json
from pathlib import Path
import unittest
from falsum.phase3y_recorded_evidence import check, EvidenceError

ROOT=Path(__file__).resolve().parents[1]
LEDGER=ROOT/"evidence/phase3y-2026-11-05-real-model-failure.json"

class Phase3YRealEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record=json.loads(LEDGER.read_text())

    def test_real_score_bits_are_4_of_8_and_zero_reversals(self):
        self.assertEqual(check(self.record), {
            "real_score_inputs":16, "repeat_verified_inferences":32,
            "provisional_matches":4, "complete_reversals":0,
            "registration_permitted":False,
        })

    def test_forged_positive_result_or_modified_scores_fail_closed(self):
        for mode in ("positive", "score_bits", "margin", "fake_expert",
                     "release", "stale_origin", "missing_case", "reversal"):
            with self.subTest(mode=mode):
                x=copy.deepcopy(self.record)
                if mode=="positive": x["verified_audit"]["provisional_matches"]=8
                if mode=="score_bits": x["score_bits_by_input"]["axios-01--A"]="0xc0000000"
                if mode=="margin": x["verified_audit"]["case_results"][0]["margin_a_minus_b"]=-9
                if mode=="fake_expert": x["verified_audit"]["independent_expert_labels"]=1
                if mode=="release": x["truth_boundaries"]["model_registration_permitted"]=True
                if mode=="stale_origin": x["source"]="https://example.org/fake"
                if mode=="missing_case": x["verified_audit"]["case_results"].pop()
                if mode=="reversal": x["verified_audit"]["counterfactual_groups"][0]["model_preference_reverses"]=True
                with self.assertRaises(EvidenceError):
                    check(x)

if __name__ == "__main__":
    unittest.main()
