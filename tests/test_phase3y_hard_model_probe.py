"""Unit tests are SYNTHETIC parser/math checks, never genuine model inferences.

The dedicated GitHub workflow runs the real official score engine and audits
its 16 actual score packets. Keep this distinction explicit in all output.
"""
import copy
import hashlib
import struct
import unittest
from unittest.mock import patch

from falsum import phase3y_hard_model_probe as mod
from falsum.phase3c_score_report import MODEL_SHA, MODEL_KECCAK, FOUNDATION_SHA
from test_phase3x_counterfactuals import mock_axios_report, mock_django_report


class Phase3YKnownHardModelProbeTests(unittest.TestCase):
    def setUp(self):
        self.ax = mock_axios_report()
        self.dj = mock_django_report()
        self.fake_tokenizer = b"fake-local-synthetic-tokenizer-not-the-official-one"
        self.fake_sha = hashlib.sha256(self.fake_tokenizer).hexdigest()

    def make(self):
        with patch.object(mod, "TOKENIZER_SHA256", self.fake_sha):
            return mod.make_inputs(self.ax,self.dj,self.fake_tokenizer,
                                   lambda text:[50281]+[111]*8+[50282])

    @staticmethod
    def synthetic_packet(score):
        bits="0x"+format(struct.unpack(">I",struct.pack(">f",score))[0],"08x")
        return {
            "intent":"SECURITY_REVIEW","class":"hybrid",
            "sha256":MODEL_SHA,"keccak256":MODEL_KECCAK,"bytes":6776908,
            "score_hex":bits,
            "manifest":{
                "intent":"SECURITY_REVIEW","class":"hybrid","abi":"lora-v1",
                "rank":8,"max_tokens":512,
                "tokenizer_hash":mod.TOKENIZER_SHA256,
                "foundation":{"hash":FOUNDATION_SHA,"version":"modernbert-base-lora16-v1"},
                "verification":{"stage1":True,"loaded":True,"repeats":2,"score_hex":bits},
            },
        }

    def predictions(self, frozen, *, constant_a=False):
        score={}
        for row in frozen["inputs"]:
            positive=(row["answer_id"]=="A") if constant_a else (
                row["answer_id"] == row["source_executed_provisional_preference"])
            score[row["id"]]=self.synthetic_packet(0.5 if positive else -0.5)
        return score

    def audited(self, frozen, predictions):
        with patch.object(mod, "TOKENIZER_SHA256", self.fake_sha):
            # Test fixture also updates official packet tokenizer to the fake hash;
            # audit still exercises all score provenance and schema checks.
            return mod.audit(frozen,predictions,self.ax,self.dj)

    def test_eight_pairwise_changed_fact_examples_and_sixteen_tokens(self):
        frozen=self.make()
        self.assertEqual(frozen["selected_case_count"],8)
        self.assertEqual(frozen["model_score_input_count"],16)
        self.assertEqual(len(frozen["inputs"]),16)
        self.assertFalse(frozen["blind_holdout"])
        self.assertEqual(frozen["independent_human_labels"],0)
        self.assertTrue(frozen["no_training_or_registration"])
        self.assertEqual(len({r["id"] for r in frozen["inputs"]}),16)
        self.assertTrue(all(r["independently_human_adjudicated"] is False for r in frozen["inputs"]))

    def test_math_synthetic_perfect_diagnostic_still_vetoes_registration(self):
        frozen=self.make()
        r=self.audited(frozen,self.predictions(frozen))
        self.assertEqual(r["provisional_matches"],8)
        self.assertEqual(r["complete_provisional_reversals"],4)
        self.assertEqual(r["constant_A_baseline_matches"],4)
        self.assertEqual(r["constant_B_baseline_matches"],4)
        self.assertEqual(r["real_score_inputs"],16)
        self.assertFalse(r["blind_holdout"])
        self.assertEqual(r["independent_expert_labels"],0)
        self.assertTrue(r["model_release_veto_remains"])
        self.assertFalse(r["automatic_registration_permitted"])
        self.assertFalse(r["network_eligible"])

    def test_constant_answer_shortcut_fails_every_reversal(self):
        frozen=self.make()
        r=self.audited(frozen,self.predictions(frozen,constant_a=True))
        self.assertEqual(r["provisional_matches"],4)
        self.assertEqual(r["complete_provisional_reversals"],0)
        self.assertTrue(all(g["model_preference_reverses"] is False for g in r["counterfactual_groups"]))

    def test_provenance_tamper_and_missing_scores_fail_closed(self):
        baseline=self.make()
        scores=self.predictions(baseline)
        for change in ("model", "repeat", "tokenizer", "input_prompt", "fake_human_label", "source_digest", "source_result"):
            with self.subTest(change=change):
                frozen=copy.deepcopy(baseline)
                packet=copy.deepcopy(scores)
                ax=copy.deepcopy(self.ax)
                if change=="model":
                    packet[next(iter(packet))]["sha256"]="0"*64
                elif change=="repeat":
                    packet[next(iter(packet))]["manifest"]["verification"]["repeats"]=1
                elif change=="tokenizer":
                    frozen["official_tokenizer_sha256"]="0"*64
                elif change=="input_prompt":
                    frozen["inputs"][0]["rendered_sha256"]="0"*64
                elif change=="fake_human_label":
                    frozen["inputs"][0]["independently_human_adjudicated"]=True
                elif change=="source_digest":
                    frozen["source_report_sha256"]["axios"]="0"*64
                elif change=="source_result":
                    ax["scenarios"][0]["patched_origin"]="https://other.example"
                with self.assertRaises((ValueError,mod.ScoreProofError)):
                    with patch.object(mod,"TOKENIZER_SHA256",self.fake_sha):
                        mod.audit(frozen,packet,ax,self.dj)
        with self.assertRaises(ValueError):
            self.audited(baseline,dict(list(scores.items())[:-1]))

    def test_cannot_pretend_isolated_function_proves_http_or_a_deployment(self):
        bad=copy.deepcopy(self.ax)
        bad["full_axios_client_or_network_execution"]=True
        with self.assertRaises(ValueError):
            mod.load_cases(bad,self.dj)
        bad=copy.deepcopy(self.dj)
        bad["full_installed_django_runtime"]=True
        with self.assertRaises(ValueError):
            mod.load_cases(self.ax,bad)


if __name__=="__main__":
    unittest.main()