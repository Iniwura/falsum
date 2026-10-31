"""Test actual-model diagnostic bookkeeping without claiming expert accuracy."""
import copy
import math
import unittest
from unittest.mock import patch

from falsum.ai_review_benchmark import build
from falsum.ai_review_model_probe import ProvisionalProbeError, _verify, evaluate
from test_ai_review_benchmark import sample


class AIModelProbeTests(unittest.TestCase):
    def setUp(self):
        spec, queue, evidence, faux_sources = sample()
        with patch("falsum.ai_review_benchmark.build_challenges", return_value=faux_sources):
            self.public, self.key = build(spec, queue, evidence)

    def test_eight_ai_drafts_are_not_accuracy(self):
        report = evaluate(self.public, self.key, lambda q,a: 0.0)
        self.assertEqual(report["ai_proposals_compared"], 8)
        self.assertEqual(report["ai_agreement_fraction"], .5)
        self.assertEqual(report["model_agrees_with_ai_proposals"], 0)
        self.assertEqual(report["families_matching_both_ai_proposals"], 0)
        self.assertEqual(report["two_context_families"], 4)
        self.assertEqual(report["distinct_model_inferences"], 24)
        self.assertIs(report["ai_agreement_is_not_accuracy"], True)
        self.assertIs(report["network_eligible"], False)
        self.assertIs(report["model_quality_validated"], False)
        self.assertEqual(report["human_reviews"], 0)

    def test_answer_only_shortcut_cannot_win_opposed_preference(self):
        report = evaluate(self.public, self.key, lambda q,a: float(len(a)))
        self.assertEqual(report["model_agrees_with_ai_proposals"], 4)
        self.assertEqual(report["families_matching_both_ai_proposals"], 0)
        self.assertTrue(all(c["answer_only_cannot_pass_both"] for c in report["family_details"].values()))

    def test_successful_contextual_model_can_agree_with_all_drafts(self):
        conditions = [
            "A Python service uses this historical Requests version",
            "The server uses this affected aiohttp revision and publicly",
            "The service lets an authenticated but untrusted customer",
            "A Node.js backend uses this historical Axios version",
        ]
        def score(prompt,answer):
            finding=any(x in prompt for x in conditions)
            # Draft finding answers describe a risk; conditional ones do not.
            is_finding = "Flag" in answer or "flag" in answer
            return 1.0 if finding == is_finding else 0.0
        report = evaluate(self.public, self.key, score)
        # This checks only metric plumbing on deliberately authored fake scores.
        self.assertGreaterEqual(report["model_agrees_with_ai_proposals"], 4)
        self.assertFalse(report["model_quality_validated"])

    def test_source_status_promotion_fails(self):
        for key,val in (("network_eligible",True),("model_training_authorized",True),
                        ("human_reviews",2),("sealed_holdout",True)):
            with self.subTest(key=key):
                p=copy.deepcopy(self.public)
                p[key]=val
                with self.assertRaises(ProvisionalProbeError):
                    _verify(p,self.key)

    def test_key_hash_mutation_fails(self):
        key=copy.deepcopy(self.key)
        key["public_packet_sha256"]="f"*64
        with self.assertRaisesRegex(ProvisionalProbeError, "tampered"):
            _verify(self.public,key)

    def test_faked_human_or_eligible_entry_fails(self):
        for field in ("human_validated","eligible"):
            with self.subTest(field=field):
                key=copy.deepcopy(self.key)
                key["entries"][0][field]=True
                with self.assertRaisesRegex(ProvisionalProbeError, "promoted"):
                    _verify(self.public,key)

    def test_provisional_label_change_does_not_bypass_context_pair(self):
        key=copy.deepcopy(self.key)
        key["entries"][1]["proposed_kind"]="finding"
        with self.assertRaisesRegex(ProvisionalProbeError, "candidate text or context pair"):
            _verify(self.public,key)

    def test_nan_score_or_boolean_fails_closed(self):
        for value in (math.inf,math.nan,True,False,"0.1"):
            with self.subTest(value=value):
                with self.assertRaises(ProvisionalProbeError):
                    evaluate(self.public,self.key,lambda q,a:value)

    def test_public_label_leak_refused(self):
        pub=copy.deepcopy(self.public)
        pub["cases"][0]["proposed_preferred"]="A"
        with self.assertRaisesRegex(ProvisionalProbeError,"leaked label"):
            _verify(pub,self.key)

    def test_duplicate_case_refused(self):
        pub=copy.deepcopy(self.public)
        key=copy.deepcopy(self.key)
        pub["cases"][1]=copy.deepcopy(pub["cases"][0])
        key["entries"][1]=copy.deepcopy(key["entries"][0])
        with self.assertRaises(ProvisionalProbeError):
            _verify(pub,key)


if __name__ == "__main__":
    unittest.main()
