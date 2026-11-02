"""Frozen Phase 3M evidence: never rebrand a successful tool test as Anjoman eligibility."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class Phase3MRecordedEvidence(unittest.TestCase):
    def setUp(self):
        self.r=json.loads((ROOT/"evidence/phase3m-2026-11-02.json").read_text())

    def test_source_change_and_real_ci_success(self):
        d=self.r
        self.assertEqual(d["status"],"PHASE3M_HONEST_AI_DRAFT_PREFLIGHT_VERIFIED_POOL_STATUS_UNKNOWN")
        self.assertEqual(d["merged_pr_url"],"https://github.com/Iniwura/falsum/pull/10")
        self.assertEqual(d["verified_ci_url"],"https://github.com/Iniwura/falsum/actions/runs/41419551250")
        self.assertEqual(d["workflow_conclusion"],"success")
        self.assertEqual(d["security_review_intent"],"SECURITY_REVIEW_GENERAL")
        self.assertEqual(d["code_scope"]["synthetic_only_new_phase3m_test_methods"],14)
        self.assertEqual(d["code_scope"]["fully_passing_python_versions"],["3.11","3.12","3.13"])

    def test_ai_origin_is_unverified_and_private_human_reviews_not_spoofed(self):
        d=self.r["code_scope"]
        self.assertEqual(d["ai_origin_source_kinds_supported"],["llm","synthetic","generated","model"])
        self.assertEqual(d["ai_provenance_recorded_as"],"unverified")
        self.assertTrue(d["explicit_opt_in_required"])
        self.assertTrue(d["human_review_statements_not_fabricated"])
        self.assertTrue(d["mixed_ai_and_human_origin_batches_rejected"])
        self.assertFalse(d["user_secret_or_private_key_used"])
        self.assertFalse(d["network_signature_or_upload_implemented"])

    def test_http_error_is_unknown_never_zero_claim(self):
        d=self.r["public_pool_read"]
        self.assertEqual(d["actual_live_status"],"UNAVAILABLE_HTTP_ERROR")
        self.assertIsNone(d["public_eligible_rows_count"])
        self.assertIsNone(d["public_eligible_submitters"])
        self.assertFalse(d["pool_threshold_verified"])
        self.assertFalse(d["falsum_owned_rows_checked"])

    def test_no_public_hidden_eval_material_or_network_qualification(self):
        d=self.r
        self.assertTrue(all(value==0 for value in d["network_qualification"].values()))
        self.assertIn("neither row text nor their content hashes",d["private_content_policy"])
        self.assertIn("quarantined",d["model_status"])


if __name__=="__main__":
    unittest.main()
