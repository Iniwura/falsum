"""Immutable research-grade accounting of Phase 3J authentic poor model performance.

The original reward model loaded in the official runtime. These tests prevent
future dashboards or submissions from turning that fact into certified quality.
"""
import json
from pathlib import Path
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]


def score(hex_bits):
    n=int(hex_bits.removeprefix("0x"),16)
    return struct.unpack(">f",struct.pack(">I",n))[0]


class Phase3JActualModelScoreRecord(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3j-2026-11-02.json").read_text())

    def test_source_and_model_are_original_real_verified_assets(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE3J_VERIFIED_REAL_FOUNDATION_MODEL_KNOWN_FAMILY_CONTEXT_FAILURE_NOT_HOLDOUT")
        self.assertEqual(e["real_scoring_ci"],"https://github.com/Iniwura/falsum/actions/runs/41411984601")
        self.assertEqual(e["merged_pr"],"https://github.com/Iniwura/falsum/pull/7")
        self.assertEqual(e["real_ci_job_conclusion"],"success")
        self.assertEqual(e["original_model_sha256"],"3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc")
        self.assertEqual(e["shared_foundation_version"],"modernbert-base-lora16-v1")
        self.assertFalse(e["original_model_retrained_in_phase"])
        self.assertEqual(e["source_runtime_workflows"]["starlette"],"https://github.com/Iniwura/falsum/actions/runs/41409503521")
        self.assertEqual(e["source_runtime_workflows"]["requests"],"https://github.com/Iniwura/falsum/actions/runs/41410209502")

    def test_recalculate_actual_float32_preferences_and_provisional_failures(self):
        x=self.e["observed"]
        self.assertEqual(x["genuine_input_scores"],8)
        self.assertEqual(x["repeated_inference_calls"],16)
        self.assertEqual(x["families_tested"],2)
        self.assertEqual(x["families_reversing_on_changed_runtime_fact"],0)
        self.assertEqual(x["families_matching_both_researcher_provisional_runtime_rules"],0)
        self.assertEqual(x["contexts_matching_researcher_provisional_runtime_rules"],2)
        self.assertEqual(len(x["float32_score_bits_by_input"]),8)
        self.assertEqual(len(x["families"]),2)
        names=("starlette-path-boundary","requests-proxy-auth")
        self.assertEqual([f["family"] for f in x["families"]],list(names))
        matched=0
        reversed_count=0
        for family in x["families"]:
            rows=family["contexts"]
            self.assertEqual([r["context"] for r in rows],["affected","fixed"])
            for row in rows:
                context=row["context"]
                ids=[k for k in x["float32_score_bits_by_input"] if k.startswith(family["family"]+"--"+context+"--")]
                self.assertEqual(len(ids),2)
                a,b=map(lambda k:score(x["float32_score_bits_by_input"][k]),ids)
                self.assertEqual(a,row["score_first_answer_f32"])
                self.assertEqual(b,row["score_second_answer_f32"])
                self.assertEqual(a-b,row["margin_first_minus_second"])
                first=ids[0].split("--")[-1]
                second=ids[1].split("--")[-1]
                chosen=first if a>b else second if a<b else "TIE"
                self.assertEqual(chosen,row["model_preferred"])
                self.assertEqual(chosen==row["provisional_runtime_expected"],row["matched_provisional"])
                matched+=int(row["matched_provisional"])
            reversed_by_scores=(rows[0]["model_preferred"]!=rows[1]["model_preferred"])
            self.assertEqual(reversed_by_scores,family["ranking_reversed"])
            reversed_count+=int(reversed_by_scores)
            self.assertFalse(family["both_contexts_matched"])
        self.assertEqual((matched,reversed_count),(2,0))

    def test_strict_no_release_even_if_scores_load(self):
        e=self.e
        self.assertEqual(e["independent_expert_labels"],0)
        self.assertFalse(e["blind_untouched_holdout"])
        self.assertEqual(e["accepted_anjoman_evaluation_rows"],0)
        self.assertEqual(e["accepted_training_pairs"],0)
        self.assertFalse(e["model_security_accuracy_certified"])
        self.assertEqual(e["existing_phase3d_reversals_passed"],"0/2")
        self.assertFalse(e["automatic_model_registration_permitted"])
        self.assertFalse(e["registered_evaluator"])
        self.assertFalse(e["network_eligible"])


if __name__=="__main__":
    unittest.main()
