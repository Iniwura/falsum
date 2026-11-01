"""Keep genuine loaded Foundation evidence distinct from model security correctness."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class RealFoundationScoreEvidence(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3c-2026-11-01.json").read_text(encoding="utf-8"))

    def test_actual_loaded_scored_run_and_exact_f32_bits(self):
        e=self.e
        self.assertEqual(e["verified_gitHub_actions_run"],
                         "https://github.com/Iniwura/falsum/actions/runs/41306369871")
        self.assertEqual(e["artifact_id"],13082973270)
        self.assertTrue(e["actual_experiment"]["real_foundation_onnx_loaded"])
        self.assertTrue(e["actual_experiment"]["real_wasi_engine_loaded"])
        self.assertEqual(e["actual_experiment"]["token_lengths"],[100,93])
        self.assertEqual(e["actual_experiment"]["total_real_scores"],4)
        self.assertTrue(e["actual_experiment"]["exact_repeat_f32_bits_verified"])
        self.assertEqual(e["actual_experiment"]["cautious_answer_score_hex"],"0xbf52c0e6")
        self.assertEqual(e["actual_experiment"]["overclaim_answer_score_hex"],"0xbf80182c")
        self.assertGreater(e["actual_experiment"]["observed_cautious_minus_overclaim_margin"],0)

    def test_exact_model_and_official_foundation_are_pinned(self):
        p=self.e["model"]
        self.assertEqual(p["sha256"],"3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc")
        self.assertEqual(p["keccak256"],"0xf8f94708f30ed31b6f0825dbffb235fa60b0e71b76fde39dbc696cf277ef8aa7")
        self.assertEqual(p["class"],"hybrid")
        self.assertEqual(p["rank"],8)
        self.assertEqual(p["safetensors_bytes"],6776908)
        a=self.e["published_assets"]
        self.assertTrue(a["all_downloaded_sha256_verified"])
        self.assertEqual(a["foundation_onnx_sha256"],
                         "0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6")
        self.assertEqual(a["official_tokenizer_sha256"],
                         "67bc76f8b9386efba1a761c1c8e5ad439fd0eaf1c2826e9dd1a205c7af4dc456")

    def test_no_fake_generalization_eligibility_or_registration(self):
        e=self.e
        c=e["constraints"]
        self.assertFalse(c["context_reversal_generalization_proven"])
        self.assertEqual(c["original_separate_diagnostic_correct_context_families"],"0/3")
        self.assertFalse(c["network_hidden_evaluation_passed"])
        self.assertFalse(c["actual_registered_evaluator"])
        self.assertFalse(c["certified_security_accuracy"])
        self.assertFalse(c["runnable_production_endpoint_available"])
        self.assertFalse(c["network_eligible"])
        self.assertEqual(c["independent_real_appsec_label_count"],0)
        self.assertEqual(c["actually_eligible_anjoman_rows"],0)
        x=e["actual_experiment"]
        self.assertFalse(x["model_accuracy_certified"])
        self.assertFalse(x["independent_expert_adjudication"])

    def test_ci_counts_represent_executed_real_foundation_and_full_suite(self):
        t=self.e["regression"]
        self.assertEqual(t["focused_phase3c_score_tests"],12)
        self.assertEqual(t["focused_old_checkpoint_tests"],7)
        self.assertEqual(t["total_focused_tests"],19)
        self.assertEqual(t["full_foundation_suite_tests"],495)
        self.assertEqual(t["full_foundation_suite_skipped"],1)
        self.assertEqual(t["phase3c_actual_model_ci_conclusion"],"success")
        self.assertEqual(t["full_foundation_suite_conclusion"],"success")
        self.assertEqual(t["official_data_gate_conclusion"],"success")


if __name__=="__main__":
    unittest.main()
