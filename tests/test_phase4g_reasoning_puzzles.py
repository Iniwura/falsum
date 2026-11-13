"""Phase 4G: author-position bias, content authenticity and source-logic tests.

Original upstream real source re-verification is a separate CI step; these
tests use Phase 3F synthetic Git API fixtures only for structural checks.
"""
import copy
import json
import unittest

from falsum.phase3f_multifamily_material import generate
from falsum.phase4g_reasoning_puzzles import (
    build, SPECS, keyword_choice, validate_source, STATUS,
)
from falsum.phase4g_safe_microprobes import run_py_probes
from test_phase3f_multifamily_material import inputs, mock_commit

class SourceSpecificResearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.synthetic_source = generate(*inputs(),fetcher=mock_commit)

    def test_seven_prior_projects_have_two_new_conditions_each(self):
        cases,check = build(self.synthetic_source)
        self.assertEqual(cases["status"],STATUS)
        self.assertEqual(len(cases["cases"]),14)
        self.assertEqual(cases["source_verified_upstream_projects"],7)
        self.assertEqual(cases["position_swapped_display_conditions"],28)
        self.assertEqual(cases["new_independent_human_gold_labels"],0)
        self.assertEqual(cases["new_anjoman_eligible_rows"],0)
        self.assertEqual(cases["actual_model_evaluations_on_this_set"],0)
        self.assertFalse(cases["network_registered_evaluator"])
        self.assertFalse(cases["blind_project_holdout"])
        self.assertTrue(cases["author_hypotheses_are_not_gold"])
        self.assertEqual(len({x["source_case_id"] for x in cases["cases"]}),7)

    def test_swap_preserves_same_text_and_sha_and_no_label(self):
        data,_=build(self.synthetic_source)
        for row in data["cases"]:
            first,swapped=row["presentations"]
            self.assertEqual(first["variant"],"original")
            self.assertEqual(swapped["variant"],"swapped")
            for i in range(2):
                self.assertEqual(first["candidate_answers"][i]["sha256"],
                                 swapped["candidate_answers"][1-i]["sha256"])
                self.assertEqual(first["candidate_answers"][i]["text"],
                                 swapped["candidate_answers"][1-i]["text"])
            self.assertIsNone(row["expert_label"])
            self.assertFalse(row["independent_human_reviewer_verified"])
            self.assertFalse(row["trainable"])
            self.assertFalse(row["network_eligible"])
            self.assertFalse(row["real_app_exploited"])
            self.assertEqual(first["model_score"],None)
            self.assertEqual(swapped["model_score"],None)

    def test_simple_lexical_shortcut_does_not_win(self):
        pack,diag=build(self.synthetic_source)
        self.assertEqual(diag["author_A_positions"],7)
        self.assertEqual(diag["author_B_positions"],7)
        self.assertGreaterEqual(diag["language_shortcut_author_agreements"],0)
        self.assertLess(diag["language_shortcut_author_agreements"],12)
        self.assertEqual(diag["cases"],14)
        self.assertTrue(diag["language_shortcut_on_14_cases_is_not_security_accuracy"])
        self.assertFalse(diag["independent_ground_truth"])
        self.assertIsNone(diag["model_quality_improvement"])
        self.assertNotIn("author_correct",json.dumps(pack))

    def test_forged_prior_source_is_rejected(self):
        for key,val in [
            ("research_only",False),("independent_human_labels",1),
            ("registered_evaluator",True),("external_source_revisions_verified",7),
        ]:
            with self.subTest(key=key):
                source=copy.deepcopy(self.synthetic_source)
                source[key]=val
                with self.assertRaises(ValueError):
                    build(source)
        source=copy.deepcopy(self.synthetic_source)
        source["review_packets"][0]["fix_commit"]="0"*40
        with self.assertRaises(ValueError):
            build(source)
        source=copy.deepcopy(self.synthetic_source)
        source["review_packets"][0]["human_preference"]="A"
        with self.assertRaises(ValueError):
            build(source)

    def test_safe_source_derived_python_microprobes(self):
        r=run_py_probes()
        self.assertEqual(r["isolated_behavior_checks"],10)
        self.assertEqual(r["source_packages_actually_installed_and_tested"],0)
        self.assertEqual(r["production_app_exploits"],0)
        self.assertEqual(r["independent_expert_gold_labels"],0)
        self.assertIsNone(r["trained_model_accuracy"])

if __name__ == "__main__":
    unittest.main()
