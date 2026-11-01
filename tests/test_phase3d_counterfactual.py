"""Phase 3D: source-fact reversals, fake loaded results, and score-integrity attacks."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from falsum.phase3c_score_inputs import TOKENIZER_SHA256
from falsum.phase3c_score_report import ScoreProofError
from falsum.phase3d_counterfactual_inputs import FAMILIES, construct, CounterfactualInputError
from falsum.phase3d_counterfactual_report import compare
from test_phase3c_score_proof import official_response


def packet():
    data=b"phase3d-local-test-tokenizer"
    def encode(text):
        n=sum(text.encode())%300
        return [50281,107,109,112,212,n,301,50282]
    with patch("falsum.phase3c_score_inputs.TOKENIZER_SHA256",hashlib.sha256(data).hexdigest()):
        result=construct(data,encode)
    result["official_tokenizer_sha256"]=TOKENIZER_SHA256
    return result


def model_responses(inputs,aligned=True):
    answers={}
    for r in inputs["inputs"]:
        good=r["answer_id"]==r["provisional_rule_based_preferred_answer"]
        high=good if aligned else not good
        answers[r["id"]]=official_response(score="0x40000000" if high else "0x3f800000")
    return answers


class RealCounterfactualTrustTests(unittest.TestCase):
    def test_two_families_four_contexts_eight_sources(self):
        d=packet()
        self.assertEqual(len(d["inputs"]),8)
        self.assertEqual(d["context_counterfactual_families"],2)
        self.assertEqual({r["family"] for r in d["inputs"]},
                         {"installed-version","symlink-flag"})
        self.assertFalse(d["unseen_or_blind_holdout"])
        self.assertEqual(d["independent_expert_labels"],0)
        self.assertFalse(d["network_eligible"])

    def test_answers_identical_across_contexts_not_just_similar(self):
        d=packet()
        for f in FAMILIES:
            family=[x for x in d["inputs"] if x["family"]==f["family"]]
            self.assertEqual(len(family),4)
            self.assertEqual(len({x["task_sha256"] for x in family}),2)
            for answer_id,_ in f["fixed_answers"]:
                self.assertEqual(len({r["answer_sha256"] for r in family
                                     if r["answer_id"]==answer_id}),1)

    def test_provisional_rules_opposite_for_each_context(self):
        d=packet()
        for family in ("installed-version","symlink-flag"):
            cases={r["context"]:r["provisional_rule_based_preferred_answer"]
                   for r in d["inputs"] if r["family"]==family}
            self.assertEqual(len(set(cases.values())),2)

    def test_expected_success_does_not_certify_network_or_expert_accuracy(self):
        d=packet()
        report=compare(d,model_responses(d,aligned=True))
        self.assertEqual(report["families_with_preference_reversal"],2)
        self.assertEqual(report["families_matching_both_provisional_expected_preferences"],2)
        self.assertEqual(report["real_inference_calls_including_repeats"],16)
        self.assertEqual(report["labels_human_adjudicated"],0)
        self.assertTrue(report["rule_derived_not_independent_accuracy"])
        self.assertFalse(report["network_eligible"])

    def test_model_wrong_in_both_contexts_must_not_be_reported_as_success(self):
        d=packet()
        report=compare(d,model_responses(d,aligned=False))
        self.assertEqual(report["families_with_preference_reversal"],2)
        self.assertEqual(report["families_matching_both_provisional_expected_preferences"],0)
        self.assertFalse(report["registered_evaluator"])

    def test_static_answer_bias_no_reversal_is_detected(self):
        d=packet()
        all_a={r["id"]:official_response("0x40000000" if r["answer_id"] in
               ("not-affected","flag-not-met") else "0x3f800000") for r in d["inputs"]}
        report=compare(d,all_a)
        self.assertEqual(report["families_with_preference_reversal"],0)
        self.assertEqual(report["families_matching_both_provisional_expected_preferences"],0)
        self.assertFalse(report["network_eligible"])

    def test_ties_do_not_count_as_reversals(self):
        d=packet()
        eq={r["id"]:official_response() for r in d["inputs"]}
        report=compare(d,eq)
        self.assertEqual(report["families_with_preference_reversal"],0)

    def test_missing_real_foundation_runtime_output_fails_closed(self):
        d=packet()
        answers=model_responses(d)
        first=d["inputs"][0]["id"]
        answers[first]["manifest"]["verification"]["loaded"]=False
        with self.assertRaises(ScoreProofError):
            compare(d,answers)

    def test_wrong_model_and_nonfinite_scores_fail_closed(self):
        d=packet()
        for key,value in (("sha256","0"*64),("class","judgment"),("score_hex","0x7f800000")):
            with self.subTest(key=key):
                answers=model_responses(d)
                answers[d["inputs"][0]["id"]][key]=value
                with self.assertRaises(ScoreProofError):
                    compare(d,answers)

    def test_missing_or_duplicated_ids_fail_closed(self):
        d=packet()
        answers=model_responses(d)
        answers.pop(d["inputs"][0]["id"])
        with self.assertRaises(ScoreProofError):
            compare(d,answers)
        d2=copy.deepcopy(d)
        d2["inputs"][1]["id"]=d2["inputs"][0]["id"]
        with self.assertRaises(ScoreProofError):
            compare(d2,model_responses(d))

    def test_wrong_rule_promotion_and_expert_label_blocked(self):
        d=packet()
        for field,bad in (("network_eligible",True),
                          ("independent_expert_labels",1),
                          ("unseen_or_blind_holdout",True),
                          ("candidate_answer_bytes_fixed_within_each_family",False),
                          ("official_tokenizer_sha256","f"*64)):
            with self.subTest(field=field):
                x=copy.deepcopy(d)
                x[field]=bad
                with self.assertRaises(ScoreProofError):
                    compare(x,model_responses(d))

    def test_forged_answer_content_or_context_fails_closed(self):
        d=packet()
        for key,bad in (("answer_sha256","0"*64),
                        ("task_sha256","0"*64),
                        ("rendered_input_sha256","0"*64),
                        ("provisional_rule_based_preferred_answer","fabricated")):
            with self.subTest(key=key):
                x=copy.deepcopy(d);x["inputs"][0][key]=bad
                with self.assertRaises(ScoreProofError):
                    compare(x,model_responses(d))

    def test_invalid_token_ids_fail_closed(self):
        d=packet()
        x=copy.deepcopy(d)
        x["inputs"][0]["input_ids"][0]=999
        with self.assertRaises(ScoreProofError):
            compare(x,model_responses(d))

    def test_tokenizer_is_byte_sha_bound(self):
        with self.assertRaises(ValueError):
            construct(b"not official",lambda x:[50281,2,3,4,5,6,7,50282])


if __name__=="__main__":
    unittest.main()
