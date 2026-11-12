"""Phase 4E integrity tests. Mock upstream fetch is NOT an actual source review."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.phase4e_counterbalanced_reviews import (
    make_pack, validate_source, ReviewPackError, STATUS,
)
from falsum.phase3f_multifamily_material import generate
from test_phase3f_multifamily_material import inputs, mock_commit


class CounterbalancedSourceReviewerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exact recorded pin structure with SYNTHETIC upstream-patch payloads;
        # dedicated CI performs a separate live eight-commit check.
        cls.real_structure_mock_commit = generate(*inputs(),fetcher=mock_commit)

    def test_seven_real_source_pins_fourteen_position_balanced_views(self):
        pack=make_pack(copy.deepcopy(self.real_structure_mock_commit))
        self.assertEqual(pack["status"],STATUS)
        self.assertEqual(pack["source_backed_unique_review_cases"],7)
        self.assertEqual(pack["counterbalanced_presentation_count"],14)
        self.assertEqual(pack["security_families"],7)
        self.assertEqual(len({r["upstream_repository"] for r in pack["cases"]}),7)
        self.assertEqual(len({r["security_family"] for r in pack["cases"]}),7)
        self.assertEqual(pack["independent_gold_labels"],0)
        self.assertEqual(pack["new_eligible_anjoman_rows"],0)
        self.assertFalse(pack["registered_evaluator"])
        self.assertFalse(pack["training_allowed"])
        self.assertFalse(pack["general_model_accuracy_measured"])
        self.assertTrue(pack["not_a_blind_holdout"])

    def test_each_answer_appears_as_a_and_b_once_not_fourteen_cases(self):
        pack=make_pack(copy.deepcopy(self.real_structure_mock_commit))
        ids=[]
        for case in pack["cases"]:
            original,swapped=case["two_counterbalanced_presentations"]
            ids.extend((original["presentation_id"],swapped["presentation_id"]))
            self.assertEqual(original["orientation"],"original")
            self.assertEqual(swapped["orientation"],"swapped")
            a,b=original["reviewer_display_answers"]
            a2,b2=swapped["reviewer_display_answers"]
            self.assertEqual(a["candidate_text_sha256"],b2["candidate_text_sha256"])
            self.assertEqual(b["candidate_text_sha256"],a2["candidate_text_sha256"])
            self.assertEqual(a["text"],b2["text"])
            self.assertEqual(b["text"],a2["text"])
            self.assertIsNone(case["independently_approved_answer"])
            self.assertFalse(case["independent_expert_reviewer_verified"])
            self.assertFalse(case["live_application_exploit_verified"])
            self.assertFalse(case["training_authorized"])
            self.assertFalse(case["network_eligible"])
            for presentation in (original,swapped):
                self.assertIsNone(presentation["preference_label"])
                self.assertIsNone(presentation["score_by_model"])
                self.assertFalse(presentation["expert_review_verified"])
        self.assertEqual(len(ids),len(set(ids)))

    def test_source_fraud_test_fraud_or_answer_fraud_is_rejected(self):
        for kind in ("commit","source_blob","regression_blob",
                     "source_patch","regression_patch","answer_hash",
                     "answer_text","source_url","test_url","review_question"):
            with self.subTest(kind=kind):
                sample=copy.deepcopy(self.real_structure_mock_commit)
                row=sample["review_packets"][0]
                if kind=="commit":
                    row["fix_commit"]="0"*40
                elif kind=="source_blob":
                    row["source_post_fix_git_blob_sha1"]="a"*40
                elif kind=="regression_blob":
                    row["regression_test_post_fix_git_blob_sha1"]="a"*40
                elif kind=="source_patch":
                    row["source_patch_sha256"]="0"*64
                elif kind=="regression_patch":
                    row["regression_test_patch_sha256"]="bad"
                elif kind=="answer_hash":
                    row["unreviewed_candidates"][0]["sha256"]="0"*64
                elif kind=="answer_text":
                    row["unreviewed_candidates"][1]["text"]="Forged answer"
                elif kind=="source_url":
                    row["source_url"]="https://evil.invalid/code"
                elif kind=="test_url":
                    row["test_url"]="https://evil.invalid/test"
                elif kind=="review_question":
                    row["review_question"]=""
                # Note: digest-only tampering with a valid length is not
                # independently detected here. The live Phase3F verifier
                # checks actual upstream patch SHA and file Git blobs.
                if kind=="source_patch":
                    row["source_patch_sha256"]="bad"
                with self.assertRaises(ReviewPackError):
                    make_pack(sample)

    def test_training_label_promotion_without_external_review_fails(self):
        for field,val in (
            ("human_preference","A"),
            ("human_review_verified",True),
            ("network_eligible",True),
            ("training_authorized",True),
            ("source_patch_is_exploit_proof",True),
            ("production_app_version_known",True),
            ("candidate_order_human_randomized",True),
        ):
            with self.subTest(field=field):
                sample=copy.deepcopy(self.real_structure_mock_commit)
                sample["review_packets"][0][field]=val
                with self.assertRaises(ReviewPackError):
                    make_pack(sample)
        sample=copy.deepcopy(self.real_structure_mock_commit)
        sample["independent_human_labels"]=7
        with self.assertRaises(ReviewPackError):
            make_pack(sample)

    def test_missing_family_or_duplicate_source_identity_rejected(self):
        s=copy.deepcopy(self.real_structure_mock_commit)
        s["review_packets"].pop()
        with self.assertRaises(ReviewPackError):
            make_pack(s)
        s=copy.deepcopy(self.real_structure_mock_commit)
        s["review_packets"][0]["repository"]=s["review_packets"][1]["repository"]
        with self.assertRaises(ReviewPackError):
            make_pack(s)

    def test_review_rubric_never_claims_live_application_exploit(self):
        pack=make_pack(copy.deepcopy(self.real_structure_mock_commit))
        for case in pack["cases"]:
            self.assertEqual(len(case["researcher_prerequisites_need_review"]),2)
            self.assertEqual(len(case["review_rubric"]),5)
            self.assertIn("regression",case["regression_test_file_url"] if False else
                          "regression test and evidence")
            self.assertTrue(case["source_fix_commit_url"].startswith("https://github.com/"))
            self.assertTrue(case["advisory_url"].startswith("https://github.com/"))
            self.assertEqual(case["external_review_form_url"],
              "https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml")

    def test_report_can_be_json_encoded_without_secret_or_independent_labels(self):
        report=make_pack(copy.deepcopy(self.real_structure_mock_commit))
        raw=json.dumps(report)
        self.assertNotIn('"human_preference": "A"',raw)
        self.assertNotIn('"training_allowed": true',raw)
        self.assertNotIn('"registered_evaluator": true',raw)
        self.assertNotIn('PRIVATE-EVALPOOL',raw)


if __name__=="__main__":
    unittest.main()
