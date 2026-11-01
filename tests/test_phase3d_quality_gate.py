"""Regression: a real loaded LoRA with failed version reversal cannot ship."""
import copy
import json
import unittest
from pathlib import Path

from falsum.phase3d_quality_gate import assess, QualityGateError
from falsum.phase3d_counterfactual_report import STATUS

ROOT=Path(__file__).resolve().parents[1]


def report(reversal=False,both=False):
    cases=[]
    for family in ("installed-version","symlink-flag"):
        contexts=[{"diagnostic_matches_provisional_rule":True},
                  {"diagnostic_matches_provisional_rule":False}]
        cases.append({
            "family":family,"contexts":contexts,
            "ranking_reverses_when_one_deployment_fact_changes":reversal,
            "both_context_preferences_match_provisional_rule":both})
    return {
        "status":STATUS,"actual_official_foundation_loaded":True,
        "repeat_float32_bits_identical":True,
        "real_inference_calls_including_repeats":16,
        "families_tested":2,
        "rule_derived_not_independent_accuracy":True,
        "labels_human_adjudicated":0,
        "network_eligible":False,"registered_evaluator":False,
        "counterfactual_families":cases,
        "families_with_preference_reversal":2 if reversal else 0,
        "families_matching_both_provisional_expected_preferences":2 if both else 0,
    }


class QualityVetoTests(unittest.TestCase):
    def test_failed_reversal_blocks(self):
        g=assess(report())
        self.assertEqual(g["families_reversing"],0)
        self.assertEqual(g["families_matching_both_provisional_rules"],0)
        self.assertEqual(g["contexts_matching_provisional_rules"],2)
        self.assertTrue(g["diagnostic_model_failed_context_test"])
        self.assertEqual(g["action"],"BLOCK_MODEL_RELEASE_AND_REGISTRATION_PENDING_QUALITY_REMEDIATION")
        self.assertFalse(g["network_eligible"])
        self.assertFalse(g["automatic_registration_permitted"])

    def test_even_full_synthetic_success_not_independent_label_or_release(self):
        r=report(reversal=True,both=True)
        for f in r["counterfactual_families"]:
            for row in f["contexts"]:
                row["diagnostic_matches_provisional_rule"]=True
        g=assess(r)
        self.assertEqual(g["families_reversing"],2)
        self.assertEqual(g["families_matching_both_provisional_rules"],2)
        self.assertFalse(g["diagnostic_model_failed_context_test"])
        self.assertFalse(g["automatic_registration_permitted"])
        self.assertTrue(g["must_obtain_independent_human_labels"])

    def test_do_not_trust_forged_runtime_or_registration(self):
        for k,bad in (("actual_official_foundation_loaded",False),
                      ("repeat_float32_bits_identical",False),
                      ("real_inference_calls_including_repeats",0),
                      ("network_eligible",True),("registered_evaluator",True),
                      ("labels_human_adjudicated",1)):
            with self.subTest(k=k):
                x=report();x[k]=bad
                with self.assertRaises(QualityGateError):
                    assess(x)

    def test_wrong_model_summary_rejected(self):
        x=report();x["families_with_preference_reversal"]=2
        with self.assertRaises(QualityGateError):
            assess(x)

    def test_one_family_missing_refused(self):
        x=report();x["counterfactual_families"].pop()
        with self.assertRaises(QualityGateError):
            assess(x)


if __name__=="__main__":
    unittest.main()
