"""Phase 4F: real-review evidence gates with explicit *synthetic* adversarial fixtures."""
import copy
import json
import unittest

from falsum.phase3f_multifamily_material import generate
from falsum.phase4e_counterbalanced_reviews import make_pack
from falsum.phase3w_review_intake import assemble, reviewer_cases
from falsum.phase4f_review_evidence_gate import (
    build,validate_pack,validate_review_audit,GateError,STATUS,
)
from test_phase3f_multifamily_material import inputs,mock_commit
from test_phase3w_review_intake import fixture


class HonestBenchmarkGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Synthetic Git API objects are for tests only. Dedicated CI separately
        # recontacts and verifies actual upstream source and regression-test commits.
        cls.pack=make_pack(generate(*inputs(),fetcher=mock_commit))
        cls.rows=reviewer_cases()

    def empty(self):
        return assemble([],self.rows,fetched_live=True,pages=1)

    def test_zero_independent_reviews_means_unknown_not_false_accuracy(self):
        result=build(copy.deepcopy(self.pack),self.empty())
        self.assertEqual(result["status"],STATUS)
        self.assertEqual(result["source_verified_case_count"],7)
        self.assertEqual(result["counterbalanced_display_conditions"],14)
        self.assertEqual(result["total_public_format_valid_claims"],0)
        self.assertEqual(result["independent_expert_adjudications_accepted"],0)
        self.assertEqual(result["gold_labeled_cases"],0)
        self.assertEqual(result["actual_model_scored_cases_on_this_review_pack"],0)
        self.assertIsNone(result["source_grounded_model_accuracy"])
        self.assertIsNone(result["relative_evaluator_improvement"])
        self.assertIsNone(result["model_position_invariance_score"])
        self.assertTrue(result["not_a_sealed_project_disjoint_holdout"])
        self.assertFalse(result["release_ready_to_claim_measured_improvement"])
        self.assertTrue(result["no_model_registration_or_training"])
        self.assertEqual(len(result["cases"]),7)

    def test_two_authentic_format_valid_review_claims_still_not_gold(self):
        item=self.rows["real-requests-proxy-auth"]
        a=fixture(item,login="independentAuthorOne",answer="A",number=901)
        b=fixture(item,login="independentAuthorTwo",answer="B",number=902)
        intake=assemble([a,b],self.rows,fetched_live=True,pages=1)
        result=build(self.pack,intake)
        self.assertEqual(result["total_public_format_valid_claims"],2)
        row=next(r for r in result["cases"] if r["case_id"]==item["id"])
        self.assertEqual(row["published_unverified_opinions"],["A","B"])
        self.assertEqual(len(row["published_review_issue_urls"]),2)
        self.assertTrue(row["any_disagreement_requires_human_resolution"])
        self.assertIsNone(row["independently_adjudicated_expert_gold_label"])
        self.assertEqual(result["gold_labeled_cases"],0)
        self.assertIsNone(result["constant_A_baseline_accuracy"])

    def test_single_abstaining_public_claim_does_not_certify_expertise(self):
        row=self.rows["real-jinja-attr-sandbox"]
        one=fixture(row,login="AnotherReviewer",answer="ABSTAIN",number=905)
        intake=assemble([one],self.rows)
        result=build(self.pack,intake)
        self.assertFalse(result["review_intake_fetched_live"])
        case=next(c for c in result["cases"] if c["case_id"]==row["id"])
        self.assertEqual(case["published_unverified_opinions"],["ABSTAIN"])
        self.assertFalse(case["any_disagreement_requires_human_resolution"])
        self.assertEqual(result["independent_expert_adjudications_accepted"],0)
        self.assertFalse(case["trainable_or_network_eligible"])

    def test_author_fabrication_and_false_expert_certification_are_blocked(self):
        item=self.rows["real-requests-proxy-auth"]
        intake=assemble([fixture(item)],self.rows,fetched_live=True,pages=1)
        for key,value in (
            ("independent_expert_certified_labels",1),
            ("accepted_training_pairs",1),
            ("new_eligible_anjoman_rows",5),
            ("registered_evaluator",True),
            ("security_accuracy_certified",True),
            ("trainable_preference_pairs",[{"case_id":item["id"],"gold":"A"}]),
        ):
            with self.subTest(key=key):
                forged=copy.deepcopy(intake)
                forged[key]=value
                with self.assertRaises(GateError):
                    build(self.pack,forged)
        for key,val in (
            ("source_claim_correctness_verified",True),
            ("independent_security_expertise_verified",True),
            ("training_label_accepted",True),
            ("reviewer_authorship_independently_verified",True),
            ("github_author","Iniwura"),
            ("submitted_body_sha256","fake"),
            ("issue_url","https://github.com/other/falsum/issues/122"),
        ):
            with self.subTest(key=key):
                forged=copy.deepcopy(intake)
                forged["claims"][0][key]=val
                with self.assertRaises(GateError):
                    build(self.pack,forged)

    def test_position_swap_tampering_is_detected(self):
        for kind in ("swap_hash","swap_text","wrong_letter",
                     "false_label","approved_answer","training","extra_case"):
            with self.subTest(kind=kind):
                source=copy.deepcopy(self.pack)
                case=source["cases"][0]
                if kind=="swap_hash":
                    case["two_counterbalanced_presentations"][1]["reviewer_display_answers"][1]["candidate_text_sha256"]="0"*64
                elif kind=="swap_text":
                    case["two_counterbalanced_presentations"][1]["reviewer_display_answers"][1]["text"]="A shorter fabricated reviewer answer"
                elif kind=="wrong_letter":
                    case["two_counterbalanced_presentations"][0]["reviewer_display_answers"][0]["display_position"]="B"
                elif kind=="false_label":
                    case["two_counterbalanced_presentations"][0]["preference_label"]="A"
                elif kind=="approved_answer":
                    case["independently_approved_answer"]="A"
                elif kind=="training":
                    source["training_allowed"]=True
                else:
                    source["cases"].append(copy.deepcopy(case))
                with self.assertRaises(GateError):
                    build(source,self.empty())

    def test_census_mismatches_or_duplicate_claims_fail_closed(self):
        item=self.rows["real-requests-proxy-auth"]
        claim=fixture(item,number=990)
        audit=assemble([claim],self.rows)
        bad=copy.deepcopy(audit)
        bad["public_format_valid_claims"]=100
        with self.assertRaises(GateError):
            build(self.pack,bad)
        bad=copy.deepcopy(audit)
        bad["claims"].append(copy.deepcopy(bad["claims"][0]))
        bad["public_format_valid_claims"]=2
        with self.assertRaises(GateError):
            build(self.pack,bad)
        bad=copy.deepcopy(audit)
        bad["coverage"][0]["format_valid_distinct_github_claims"]=2
        with self.assertRaises(GateError):
            build(self.pack,bad)

    def test_no_material_leakage_or_automatic_quality_metrics(self):
        result=build(self.pack,self.empty())
        serialized=json.dumps(result)
        self.assertNotIn('"source_grounded_model_accuracy": 1.0',serialized)
        self.assertNotIn('"relative_evaluator_improvement": 1.0',serialized)
        self.assertNotIn("training_approved",serialized)
        self.assertEqual(result["new_anjoman_eligible_pairs"],0)
        self.assertIn("claim",result["notice"].lower())


if __name__=="__main__":
    unittest.main()
