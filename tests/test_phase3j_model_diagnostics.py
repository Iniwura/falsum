"""Offline tests for real-model score provenance and provisional-label quarantine."""
from pathlib import Path
import copy
import json
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3j_inputs import FAMILIES, Phase3JError, construct, proof
from falsum.phase3j_model_report import analyze
from falsum.phase3c_score_report import (
    MODEL_SHA, MODEL_KECCAK, FOUNDATION_SHA, FOUNDATION_VERSION,
    ScoreProofError,
)
from falsum.phase3c_score_inputs import TOKENIZER_SHA256

ROOT=Path(__file__).resolve().parents[1]


def fake_tokens(_text):
    return [50281, 123, 234, 345, 456, 567, 678, 50282]


def official_fake_score(bit_string):
    """Synthesized unit fixture; NEVER a claim of real inference."""
    return {
        "intent":"SECURITY_REVIEW", "class":"hybrid",
        "sha256":MODEL_SHA,"keccak256":MODEL_KECCAK,"bytes":6776908,
        "score_hex":bit_string,
        "manifest":{
            "intent":"SECURITY_REVIEW","class":"hybrid","abi":"lora-v1",
            "rank":8,"max_tokens":512,"tokenizer_hash":TOKENIZER_SHA256,
            "foundation":{"hash":FOUNDATION_SHA,"version":FOUNDATION_VERSION},
            "verification":{"stage1":True,"loaded":True,"repeats":2,
                            "score_hex":bit_string},
        },
    }


def make_input():
    with patch("falsum.phase3j_inputs.validate_tokenizer",return_value=None):
        return construct(ROOT,b"synthetic-not-real-tokenizer",fake_tokens)


def fake_scores(inputs, success=True):
    scores={}
    # Synthetic values intentionally all 1.0 for first answer, 0.5 for second:
    # no context reversal, showing score collection does not gate on success.
    for r in inputs["inputs"]:
        first=r["answer_id"]==next(f for f in FAMILIES if f["id"]==r["family"])["answers"][0][0]
        scores[r["id"]]=official_fake_score("0x3f800000" if first else "0x3f000000")
    return scores


class Phase3JModelQualityBoundary(unittest.TestCase):
    def test_existing_two_real_runtime_provenance_pinned(self):
        x=proof(ROOT)
        self.assertEqual(x["phase3h_runtime_workflow"],"https://github.com/Iniwura/falsum/actions/runs/41409503521")
        self.assertEqual(x["phase3i_runtime_workflow"],"https://github.com/Iniwura/falsum/actions/runs/41410209502")

    def test_eight_frozen_context_answer_combinations(self):
        x=make_input()
        self.assertEqual(x["score_input_count"],8)
        self.assertEqual(x["context_count"],4)
        self.assertEqual(x["model_family_count"],2)
        self.assertFalse(x["unseen_blind_holdout"])
        self.assertEqual(x["independent_expert_labels"],0)
        self.assertTrue(x["existing_model_release_veto_still_applies"])
        for f in FAMILIES:
            parts=[r for r in x["inputs"] if r["family"]==f["id"]]
            self.assertEqual(len(parts),4)
            for answer_id,_ in f["answers"]:
                self.assertEqual(len({r["answer_sha256"] for r in parts if r["answer_id"]==answer_id}),1)
            self.assertEqual({r["provisional_runtime_rule_preferred"] for r in parts},
                             {a[0] for a in f["answers"]})

    def test_synthetic_unit_score_can_record_failing_reversals(self):
        x=make_input()
        report=analyze(x,fake_scores(x),ROOT)
        self.assertEqual(report["real_model_score_inputs"],8)
        self.assertEqual(report["real_inference_calls_including_repeats"],16)
        self.assertEqual(report["families_with_ranking_reversal"],0)
        self.assertEqual(report["families_matching_both_provisional_rules"],0)
        self.assertEqual(report["contexts_matching_provisional_rules"],2)
        self.assertFalse(report["blind_independent_holdout"])
        self.assertFalse(report["automatic_registration_permitted"])
        self.assertTrue(report["model_release_veto_remains"])
        self.assertEqual(report["expert_approved_labels"],0)

    def test_refuse_missing_score_packet_and_extra_result(self):
        x=make_input()
        scores=fake_scores(x)
        scores.pop(x["inputs"][0]["id"])
        with self.assertRaises(ScoreProofError):analyze(x,scores,ROOT)
        scores=fake_scores(x)
        scores["extra"]="spoof"
        with self.assertRaises(ScoreProofError):analyze(x,scores,ROOT)

    def test_wrong_model_or_fake_foundation_loading_rejected(self):
        x=make_input()
        for key,val in [("sha256","f"*64),("score_hex","0xdeadbeef")]:
            with self.subTest(key=key):
                scores=fake_scores(x)
                scores[x["inputs"][0]["id"]][key]=val
                with self.assertRaises(ScoreProofError):analyze(x,scores,ROOT)
        scores=fake_scores(x)
        scores[x["inputs"][0]["id"]]["manifest"]["verification"]["loaded"]=False
        with self.assertRaises(ScoreProofError):analyze(x,scores,ROOT)

    def test_mutating_task_or_answer_digest_refused(self):
        x=make_input()
        for key in ["task_sha256","answer_sha256","rendered_sha256"]:
            with self.subTest(key=key):
                y=copy.deepcopy(x)
                y["inputs"][0][key]="f"*64
                with self.assertRaises(ScoreProofError):analyze(y,fake_scores(y),ROOT)

    def test_false_approval_or_blind_holdout_claims_refused(self):
        x=make_input()
        for key,val in [
            ("independent_expert_labels",1),("eligible_anjoman_rows",1),
            ("network_eligible",True),("unseen_blind_holdout",True),
            ("existing_model_release_veto_still_applies",False),
            ("training_material_generated",True),
        ]:
            with self.subTest(key=key):
                y=copy.deepcopy(x);y[key]=val
                with self.assertRaises(ScoreProofError):analyze(y,fake_scores(y),ROOT)

    def test_provisional_preference_and_input_identity_cannot_be_rewritten(self):
        x=make_input()
        for field,value in [
            ("provisional_runtime_rule_preferred","fake"),
            ("id","starlette-path-boundary--fake--answer"),
            ("human_expert_approved",True),
            ("input_ids",[50281,3,50282]),
        ]:
            with self.subTest(field=field):
                y=copy.deepcopy(x);y["inputs"][0][field]=value
                with self.assertRaises(ScoreProofError):analyze(y,fake_scores(x),ROOT)

    def test_provenance_tampering_rejected_before_scores(self):
        x=make_input()
        x["source_provenance"]["phase3i_runtime_workflow"]="https://example.invalid"
        with self.assertRaises(ScoreProofError):analyze(x,fake_scores(x),ROOT)

    def test_provisional_inputs_are_bounded_and_never_truncated(self):
        with patch("falsum.phase3j_inputs.validate_tokenizer",return_value=None):
            with self.assertRaises(Phase3JError):
                construct(ROOT,b"fake",lambda _: [50281]+[4]*191+[50282])

    def test_no_existing_family_can_be_promoted_by_offline_unit_success(self):
        x=make_input()
        report=analyze(x,fake_scores(x),ROOT)
        self.assertFalse(report["registered_evaluator"])
        self.assertFalse(report["network_eligible"])
        self.assertEqual(report["new_training_pairs"],0)
        self.assertEqual(report["eligible_anjoman_rows"],0)
        self.assertFalse(report["new_model_trained"])


if __name__=="__main__":
    unittest.main()
