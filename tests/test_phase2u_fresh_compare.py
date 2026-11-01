"""Strong quarantine and context-transfer model comparator tests (no fake accuracy)."""
import copy
import json
import unittest

from falsum.phase2u_fresh_compare import (
    FreshCompareError, STATUS, compare, evaluate, verify,
)
from falsum.phase2u_fresh_transfer import construct
from test_phase2u_fresh_transfer import FreshTransferTests


def fixtures():
    test=FreshTransferTests()
    test.setUp()
    spec,sources,commit_fetch=test._offline_sources()
    public,key=construct(spec,test.train,test.old,test.prior,commit_fetch,sources.__getitem__)
    training={
        "status":"AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK",
        "network_eligible":False,"training_authorized_for_submission":False,
        "independent_human_reviews":0,"prior_ai_draft_inspected":True,
        "training_projects":[x["repository"] for x in test.train["cases"]],
    }
    return public,key,training


class FreshCompareTests(unittest.TestCase):
    def setUp(self):
        self.public,self.key,self.train=fixtures()

    def test_transfer_has_six_source_separated_tasks(self):
        pairs=verify(self.public,self.key,self.train)
        self.assertEqual(len(pairs),6)
        self.assertEqual(len({k["source_project"] for _,k in pairs}),3)

    def test_constant_model_cannot_pass_any_counterfactual_family(self):
        pairs=verify(self.public,self.key,self.train)
        result=evaluate(pairs,lambda prompt,answer:0.0)
        self.assertEqual(result["total_ai_proposals"],6)
        self.assertEqual(result["ai_proposals_matched"],0)
        self.assertEqual(result["families_matching_both_ai_proposals"],0)
        self.assertEqual(result["actual_inferences"],18)

    def test_answer_only_length_shortcut_can_match_at_most_three(self):
        pairs=verify(self.public,self.key,self.train)
        result=evaluate(pairs,lambda question,answer:float(len(answer)))
        self.assertEqual(result["ai_proposals_matched"],3)
        self.assertEqual(result["families_matching_both_ai_proposals"],0)

    def test_result_is_explicitly_not_real_accuracy(self):
        result=compare(self.public,self.key,self.train,
                       lambda p,a:0.0,lambda p,a:float(len(a)))
        self.assertEqual(result["status"],STATUS)
        self.assertFalse(result["independent_security_accuracy_certified"])
        self.assertFalse(result["network_eligible"])
        self.assertFalse(result["registered"])
        self.assertEqual(result["human_reviews"],0)
        self.assertEqual(result["accepted_evaluation_pairs"],0)
        self.assertEqual(result["change_in_ai_proposal_agreements"],3)

    def test_fake_human_verdict_refused(self):
        key=copy.deepcopy(self.key)
        key["entries"][0]["human_approved"]=True
        with self.assertRaisesRegex(FreshCompareError,"false reviewer"):
            verify(self.public,key,self.train)

    def test_forged_key_or_modified_question_refused(self):
        pub=copy.deepcopy(self.public)
        pub["cases"][0]["question"]+="changed"
        with self.assertRaisesRegex(FreshCompareError,"promoted or manipulated"):
            verify(pub,self.key,self.train)

    def test_trained_on_eval_project_is_caught(self):
        train=copy.deepcopy(self.train)
        train["training_projects"].append(self.key["entries"][0]["source_project"])
        with self.assertRaisesRegex(FreshCompareError,"included in training"):
            verify(self.public,self.key,train)

    def test_false_network_status_is_rejected(self):
        for field,value in (("network_eligible",True),("training_authorized",True),
                            ("sealed_holdout",True),("independent_human_reviews",2)):
            with self.subTest(field=field):
                pub=copy.deepcopy(self.public);pub[field]=value
                with self.assertRaises(FreshCompareError):
                    verify(pub,self.key,self.train)

    def test_non_finite_or_boolean_model_output_refused(self):
        for raw in (float("nan"),float("inf"),True,"0.0"):
            with self.subTest(raw=raw),self.assertRaises(FreshCompareError):
                evaluate(verify(self.public,self.key,self.train),lambda p,a:raw)


if __name__=="__main__":
    unittest.main()
