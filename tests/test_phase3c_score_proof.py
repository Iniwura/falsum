"""Phase 3C regression: structural PASS is not loaded runtime or model accuracy."""
import copy
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase3c_score_inputs import (
    CANDIDATES, STATUS as INPUT_STATUS, TASK, TOKEN_CAP,
    TOKENIZER_SHA256, InputError, make_inputs, validate,
)
from falsum.phase3c_score_report import (
    MODEL_SHA, MODEL_KECCAK, FOUNDATION_SHA, STATUS, ScoreProofError, report,
)


def fake_inputs():
    def encode(t):
        v=2 if t.endswith(CANDIDATES[0][1]) else 3
        return [50281, 100, 200, v, 50282]
    raw=b"mock-tokenizer-only-for-tests"
    with patch("falsum.phase3c_score_inputs.TOKENIZER_SHA256",hashlib.sha256(raw).hexdigest()):
        return make_inputs(raw,encode)


def official_response(score="0x3f800000",loaded=True,repeats=2):
    return {
        "intent":"SECURITY_REVIEW","class":"hybrid","sha256":MODEL_SHA,
        "keccak256":MODEL_KECCAK,"bytes":6776908,"score_hex":score,
        "manifest":{
            "intent":"SECURITY_REVIEW","class":"hybrid","abi":"lora-v1",
            "rank":8,"max_tokens":512,"tokenizer_hash":TOKENIZER_SHA256,
            "foundation":{"hash":FOUNDATION_SHA,"version":"modernbert-base-lora16-v1"},
            "verification":{"stage1":True,"loaded":loaded,"repeats":repeats,"score_hex":score}
        }
    }


class ScoreSmokeTests(unittest.TestCase):
    def test_real_input_requires_exact_official_tokenizer(self):
        with self.assertRaisesRegex(InputError,"noncanonical"):
            validate(b"unknown tokenizer")
        self.assertEqual(len(TOKENIZER_SHA256),64)

    def test_candidate_polarities_not_automatically_labeled(self):
        self.assertEqual(len(CANDIDATES),2)
        self.assertIn("3.10.11",TASK)
        self.assertIn("3.9.2",CANDIDATES[0][1])
        self.assertLessEqual(TOKEN_CAP,512)

    def test_bad_token_ids_or_missing_special_tokens_rejected(self):
        raw=b"unit-test-hash-override"
        with patch("falsum.phase3c_score_inputs.TOKENIZER_SHA256",hashlib.sha256(raw).hexdigest()):
            for ids in ([100]*8, [50281]+[123]*161+[50282],
                        [50281,50282],[50281,111,-1,50282]):
                with self.subTest(ids=len(ids)):
                    with self.assertRaises(InputError):
                        make_inputs(raw,lambda _:[*ids])

    def test_good_synthetic_ids_are_not_external_ground_truth(self):
        d=fake_inputs()
        self.assertEqual(d["status"],INPUT_STATUS)
        self.assertEqual(len(d["candidates"]),2)
        self.assertFalse(d["model_preference_known_in_advance"])
        self.assertEqual(d["independent_human_labels"],0)
        self.assertFalse(d["network_eligible"])

    def test_real_score_guard_will_reject_old_structural_only_stage(self):
        d=fake_inputs()
        # the fake unit fixture's hash deliberately differs from production.
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        with self.assertRaisesRegex(ScoreProofError,"foundation load"):
            report(d,official_response(loaded=False),official_response(loaded=False))

    def test_real_loaded_but_one_inference_not_enough(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        with self.assertRaises(ScoreProofError):
            report(d,official_response(repeats=1),official_response())

    def test_real_loaded_f32_score_and_repeated_are_not_accuracy(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        x=report(d,official_response(score="0x40000000"),official_response(score="0x3f800000"))
        self.assertEqual(x["status"],STATUS)
        self.assertEqual(x["actual_repeated_inferences"],4)
        self.assertEqual(x["observed_score_margin_cautious_minus_overclaim"],1.)
        self.assertFalse(x["real_world_exploit_detection_established"])
        self.assertFalse(x["source_training_quality_certified"])
        self.assertFalse(x["network_eligible"])
        self.assertFalse(x["evaluator_registered"])

    def test_reverse_preference_is_allowed_and_reported_not_hidden(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        x=report(d,official_response(score="0x3f800000"),
                 official_response(score="0x40000000"))
        self.assertEqual(x["observed_score_margin_cautious_minus_overclaim"],-1.)

    def test_refuse_pretend_loaded_or_forged_package_digest(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        for key,bad in (("sha256","0"*64),("keccak256","0"*66),
                        ("intent","OTHER"),("class","judgment")):
            with self.subTest(field=key):
                out=official_response()
                out[key]=bad
                with self.assertRaises(ScoreProofError):
                    report(d,out,official_response())

    def test_nonfinite_scores_and_invalid_hex_rejected(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        for value in ("0x7f800000","0x7fc00000","1.25","not-a-score",""):
            with self.subTest(score=value):
                with self.assertRaises(ScoreProofError):
                    report(d,official_response(score=value),official_response())

    def test_forged_model_output_metadata_cannot_be_trusted(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        x=official_response()
        x["manifest"]["verification"]["score_hex"]="0x00000000"
        with self.assertRaises(ScoreProofError):
            report(d,x,official_response())

    def test_input_labels_cannot_be_promoted_to_eligible(self):
        d=fake_inputs()
        d["official_tokenizer_sha256"]=TOKENIZER_SHA256
        for k,v in (("research_only",False),("network_eligible",True),
                    ("independent_human_labels",1)):
            with self.subTest(k=k):
                x=copy.deepcopy(d)
                x[k]=v
                with self.assertRaises(ScoreProofError):
                    report(x,official_response(),official_response())


if __name__=="__main__":
    unittest.main()
