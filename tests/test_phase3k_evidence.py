"""Permanent exact model-quality accounting for Phase 3K, never green-CI laundering."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase3KActualTrainingEvidence(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3k-2026-11-02.json").read_text())

    def test_authentic_workflow_and_actual_research_training(self):
        d=self.e
        self.assertEqual(d["status"],"PHASE3K_REAL_RESEARCH_LORA_TRAINED_NO_SEPARATE_PROJECT_TRANSFER_IMPROVEMENT")
        self.assertEqual(d["merged_pr"],"https://github.com/Iniwura/falsum/pull/8")
        self.assertEqual(d["verified_full_workflow"],"https://github.com/Iniwura/falsum/actions/runs/41413881596")
        self.assertEqual(d["workflow_conclusion"],"success")
        m=d["new_model"]
        self.assertTrue(m["real_training_performed"])
        self.assertEqual(m["trainer_commit"],"5fa5d68bbcf76aaa2093c5d0578f53462bc0e36e")
        self.assertEqual((m["epochs"],m["total_research_train_rows"]),(1,60))
        self.assertEqual(m["previous_advisory_train_rows"],52)
        self.assertEqual(m["new_opposite_context_train_rows"],8)
        self.assertEqual(m["training_source_families"],["Kludex/starlette","psf/requests"])
        self.assertEqual(m["official_training_data_shortcut_gate"],"PASS")
        t=m["official_trainer_test"]
        self.assertEqual(t["evaluated_pairs"],6)
        self.assertEqual(t["pairwise_accuracy"],1.0)
        self.assertEqual(t["length_baseline"],0.5)
        self.assertEqual(t["verdict"],"PASS")

    def test_no_old_to_new_transfer_improvement(self):
        x=self.e["actual_transfer_comparison"]
        self.assertEqual(x["comparison_source_projects"],[
            "tornadoweb/tornado","nodejs/undici","python-websockets/websockets"])
        self.assertFalse(x["projects_in_new_training"])
        self.assertTrue(x["previously_inspected_by_falsum"])
        self.assertFalse(x["sealed_untouched_holdout"])
        self.assertFalse(x["independently_human_approved_expected_preferences"])
        self.assertFalse(x["official_foundation_onnx_wasi_scorer_used"])
        self.assertEqual(x["total_provisional_evaluation_contexts"],6)
        self.assertEqual(x["source_families"],3)
        self.assertEqual(x["old_model_provisional_preferences_matched"],3)
        self.assertEqual(x["new_model_provisional_preferences_matched"],3)
        self.assertEqual(x["old_model_complete_reversals"],0)
        self.assertEqual(x["new_model_complete_reversals"],0)
        self.assertEqual(x["improvement_in_matching_contexts"],0)
        self.assertEqual(x["improvement_in_complete_reversals"],0)
        self.assertFalse(x["new_model_demonstrated_security_reasoning_improvement"])

    def test_trainer_pass_does_not_authorize_evaluator_registration(self):
        r=self.e["quality_boundary"]
        self.assertEqual(r["human_approved_security_labels"],0)
        self.assertEqual(r["accepted_anjoman_rows"],0)
        self.assertEqual(r["accepted_training_pairs_for_network"],0)
        self.assertFalse(r["registered_evaluator"])
        self.assertFalse(r["independent_model_accuracy_certified"])
        self.assertFalse(r["competition_ready"])
        self.assertFalse(r["eligible_for_network"])
        self.assertEqual(r["original_phase3d_counterfactuals"],"0/2")
        self.assertEqual(r["original_phase3j_counterfactuals"],"0/2")
        self.assertTrue(r["original_model_release_veto_remains"])
        self.assertTrue(r["new_model_release_veto"])
        self.assertFalse(self.e["new_model"]["model_registered_to_network"])
        self.assertFalse(self.e["new_model"]["model_packaged_for_current_official_foundation_runtime"])


if __name__=="__main__":
    unittest.main()
