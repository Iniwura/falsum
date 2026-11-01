"""Permanent Phase2V exact observed LoRA evidence must never become false expert accuracy."""
import json
import math
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase2VRealEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.r=json.loads((ROOT/"evidence/phase2v-2026-11-01.json").read_text(encoding="utf-8"))

    def test_inspected_training_improved_but_transfer_did_not(self):
        r=self.r
        t=r["training"]; e=r["transfer"]
        self.assertEqual(t["steps"],16)
        self.assertLessEqual(t["max_full_tokens"],t["node_max_tokens"])
        self.assertEqual(t["before"]["ai_provisional_preferences_matched"],4)
        self.assertEqual(t["after"]["ai_provisional_preferences_matched"],6)
        self.assertEqual(t["before"]["source_families_with_both_contexts_matched"],1)
        self.assertEqual(t["after"]["source_families_with_both_contexts_matched"],2)
        self.assertEqual(e["original_phase2u"]["ai_provisional_preferences_matched"],3)
        self.assertEqual(e["phase2v_treatment"]["ai_provisional_preferences_matched"],3)
        self.assertEqual(e["original_phase2u"]["source_families_both_provisional_contexts_matched"],0)
        self.assertEqual(e["phase2v_treatment"]["source_families_both_provisional_contexts_matched"],0)
        self.assertEqual(e["agreement_gain"],0)
        self.assertEqual(e["full_context_family_gain"],0)
        self.assertEqual(len(t["after_family_results"]),4)
        self.assertEqual(sum(x["both_correct_against_ai"] for x in t["after_family_results"]),2)
        for item in t["after_family_results"]:
            self.assertEqual(item["both_correct_against_ai"],
                             item["exposure_margin"]>0 and item["missing_margin"]<0)
            self.assertTrue(math.isfinite(item["exposure_margin"]))
            self.assertTrue(math.isfinite(item["missing_margin"]))

    def test_no_expert_invention_no_accepted_network_evaluator(self):
        r=self.r
        self.assertFalse(r["training"]["official_upstream_training_procedure"])
        self.assertFalse(r["conclusion"]["eligible_network_release"])
        self.assertFalse(r["conclusion"]["network_eligible"])
        self.assertFalse(r["conclusion"]["live_evaluator_registered"])
        self.assertEqual(r["conclusion"]["independent_expert_labels"],0)
        self.assertEqual(r["conclusion"]["accepted_Anjoman_evaluation_rows"],0)
        self.assertTrue(r["transfer"]["source_separated_but_not_sealed"])
        self.assertTrue(r["training"]["research_only"])
        self.assertEqual(len(set(r["transfer"]["source_projects"])&
                             set(r["training"]["training_projects"])),0)

    def test_pinned_sha_and_genuine_action_identity(self):
        r=self.r
        self.assertEqual(r["workflow_run"],"https://github.com/Iniwura/falsum/actions/runs/41285552033")
        self.assertEqual(r["workflow_artifact_id"],13075226722)
        for key in ("archive_sha256","exact_training_report_sha256",
                    "exact_external_comparison_sha256"):
            self.assertRegex(r[key],r"^[0-9a-f]{64}$")
        for key in ("starting_adapter_manifest_sha256","trained_adapter_manifest_sha256"):
            self.assertRegex(r["training"][key],r"^[0-9a-f]{64}$")
        self.assertNotEqual(r["training"]["starting_adapter_manifest_sha256"],
                            r["training"]["trained_adapter_manifest_sha256"])
        self.assertEqual(r["transfer"]["source_test_file_replays"],6)


if __name__=="__main__":
    unittest.main()
