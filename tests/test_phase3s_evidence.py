"""Phase 3S verified deployment ledger, not fake evaluator performance."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Phase3SLiveEditorialEvidence(unittest.TestCase):
    def setUp(self):
        self.r=json.loads((ROOT/"evidence/phase3s-2026-11-03-live-editorial.json").read_text())

    def test_merged_reference_redesign_and_real_qa_checks(self):
        r=self.r
        self.assertEqual(r["status"],"PHASE3S_FIRMA_REFERENCE_EDITORIAL_DEMO_MERGED_AND_VERCEL_PRODUCTION_VERIFIED")
        self.assertEqual(r["merged_commit"],"f863b7552804e98ec3d87143b50e075139446d31")
        self.assertEqual(r["pr"],"https://github.com/Iniwura/falsum/pull/17")
        self.assertTrue(r["pre_merge_validation"]["all_21_checks_green"])
        checks=r["pre_merge_validation"]["browser_click_smoke"]
        self.assertTrue(checks["after_toggle_changed_actual_source_code"])
        self.assertTrue(checks["mobile_before_after_interactions_passed"])
        self.assertEqual(checks["mobile_horizontal_overflow_px"],0)
        self.assertEqual(checks["browser_page_errors"],0)

    def test_verified_production_commit_and_real_data(self):
        d=self.r["vercel"]
        self.assertEqual(d["source_commit"],"f863b7552804e98ec3d87143b50e075139446d31")
        self.assertEqual(d["deployment_id"],"dpl_82fZz4pCvJj7yHi33Ht3XxbTocup")
        self.assertEqual(d["verified_home_http_status"],200)
        self.assertEqual(d["verified_json_http_status"],200)
        self.assertTrue(d["real_source_snippets_present"])
        self.assertTrue(d["historical_private_row_content_not_present"])
        self.assertFalse(d["unexpected_live_external_model_inference"])

    def test_no_false_mission_proof_or_model_submissions(self):
        x=self.r["bounds"]
        self.assertEqual(x["third_party_mission_apps_verified"],0)
        self.assertFalse(x["evaluator_model_registered"])
        self.assertEqual(x["new_network_rows_created_by_redesign"],0)
        self.assertFalse(x["hackathon_final_entry_submitted"])
        self.assertFalse(x["bounty_maintainer_approval_confirmed"])
        self.assertFalse(x["winning_claimed"])
        self.assertTrue(x["synthetic_local_fixtures_not_actual_mission_apps"])

    def test_source_and_docs_exist(self):
        self.assertTrue((ROOT/"src/falsum/templates/firma_editorial_evidence_lab.html").is_file())
        self.assertIn("Phase 3S",(ROOT/"docs/H2_EVALUATORS_JUDGE_PACK.md").read_text())
        self.assertIn("Firma",(ROOT/"docs/PHASE3S.md").read_text())


if __name__ == "__main__":
    unittest.main()
