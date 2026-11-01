"""Protect real Phase2U model-training evidence from false performance claims."""
import json
import math
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class RealModelEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase2u-2026-11-01.json").read_text())

    def test_official_train_success_is_not_network_acceptance(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE2U_REAL_TRAINING_FAILED_CONTEXT_TRANSFER_RESEARCH_ONLY")
        self.assertEqual(e["training_data"]["total"],60)
        self.assertEqual(e["training_data"]["prior_synthetic_GHSA_train_pairs"],52)
        self.assertEqual(e["training_data"]["new_AI_provisional_source_context_pairs"],8)
        self.assertEqual(e["training_data"]["human_approved_labels"],0)
        self.assertEqual(e["training_data"]["source_test_replays_for_train_projects"],8)
        self.assertEqual(e["training_data"]["complete_added_training_model_inputs"],16)
        self.assertLessEqual(e["training_data"]["maximum_added_input_tokens"],512)
        self.assertTrue(e["training_data"]["official_data_gate"]["passed"])
        self.assertEqual(e["real_model_training"]["official_result_verdict"],"PASS")
        self.assertEqual(e["real_model_training"]["official_result_evaluation_pairs"],6)
        self.assertEqual(e["real_model_training"]["official_result_pairwise_accuracy"],1)
        self.assertTrue(e["real_model_training"]["official_result_does_not_authorize_network_eligibility"])
        self.assertFalse(e["conclusion"]["independent_security_accuracy_measured"])
        self.assertFalse(e["conclusion"]["deployment_authorized"])
        self.assertFalse(e["conclusion"]["live_evaluator_registered"])

    def test_new_and_old_rankings_did_not_reverse_any_source_family(self):
        e=self.e
        old=e["inspected_original_four_projects_diagnostic"]
        self.assertEqual(old["frozen_model_agrees_with_AI_proposals"],4)
        self.assertEqual(old["new_model_agrees_with_AI_proposals"],4)
        self.assertEqual(old["frozen_families_with_both_contexts_correct_against_AI_proposals"],0)
        self.assertEqual(old["new_families_with_both_contexts_correct_against_AI_proposals"],0)
        new=e["fresh_source_separated_transfer"]
        self.assertEqual(new["source_families"],3)
        self.assertEqual(new["old_model_ai_proposal_agreements"],3)
        self.assertEqual(new["new_model_ai_proposal_agreements"],3)
        self.assertEqual(new["old_model_families_matching_both_provisional_contexts"],0)
        self.assertEqual(new["new_model_families_matching_both_provisional_contexts"],0)
        self.assertEqual(len(new["individual_model_cases"]),6)
        self.assertFalse(e["conclusion"]["provisional_context_transfer_improvement_observed"])
        for row in new["individual_model_cases"]:
            for key in ("original_margin","new_margin"):
                self.assertTrue(math.isfinite(row[key]))
            self.assertEqual(row["old_ai_agree"],row["original_margin"]>0)
            self.assertEqual(row["new_ai_agree"],row["new_margin"]>0)
        self.assertEqual(len(set(new["never_used_in_intervention_training"])&
                             set(e["training_data"]["research_training_projects"])),0)

    def test_source_replay_and_report_identity_pins_are_real(self):
        e=self.e
        new=e["fresh_source_separated_transfer"]
        self.assertEqual(new["verified_pre_post_source_and_regression_file_replays"],6)
        self.assertEqual(new["actual_full_model_inputs_token_checked"],12)
        self.assertEqual(new["largest_full_model_tokens"],450)
        self.assertEqual(new["source_separated_but_not_sealed"],True)
        for x in ("three_project_comparison_report_sha256","new_model_adapter_sha256",
                  "frozen_model_adapter_sha256"):
            self.assertRegex(e[x],r"^[0-9a-f]{64}$")
        self.assertNotEqual(e["frozen_model_adapter_sha256"],e["new_model_adapter_sha256"])
        self.assertEqual(e["three_project_comparison_artifact_id"],13074830234)
        self.assertEqual(e["real_model_training"]["research_epochs"],1)
        self.assertEqual(e["conclusion"]["eligible_Anjoman_evaluation_pairs"],0)
        self.assertEqual(e["conclusion"]["independent_human_reviews"],0)


if __name__=="__main__":
    unittest.main()
