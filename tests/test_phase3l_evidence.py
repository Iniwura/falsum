"""Keep Phase 3L's workflow result separate from any network acceptance claims."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase3LOfflineEvidence(unittest.TestCase):
    def setUp(self):
        self.report=json.loads((ROOT/"evidence/phase3l-2026-11-02.json").read_text())

    def test_merged_implementation_and_actual_green_synthetic_ci(self):
        r=self.report
        self.assertEqual(r["status"],"PHASE3L_OFFLINE_EVALPOOL_PREFLIGHT_VERIFIED_NO_NETWORK_ROWS_SUBMITTED")
        self.assertEqual(r["pull_request"],"https://github.com/Iniwura/falsum/pull/9")
        self.assertEqual(r["merged_commit"],"ab351b4fba6c091edf4c5db493c2e15b57871b83")
        self.assertEqual(r["verified_phase3l_ci"],"https://github.com/Iniwura/falsum/actions/runs/41417864451")
        self.assertEqual(r["workflow_conclusion"],"success")
        self.assertEqual(r["target_intent"],"SECURITY_REVIEW_GENERAL")
        self.assertEqual(r["shipped"]["passed_python_versions"],["3.11","3.12","3.13"])
        self.assertEqual(r["shipped"]["anonymous_synthetic_only_adversarial_test_methods"],17)

    def test_exact_private_unsigned_protocol_scope(self):
        r=self.report["shipped"]
        self.assertTrue(r["private_jsonl_standard_library_preflight"])
        self.assertTrue(r["local_sha256_per_row_review_claim_binding"])
        self.assertTrue(r["byte_exact_unsigned_eip191_five_line_signing_message"])
        self.assertTrue(r["no_wallet_credential_input_or_upload_implementation"])
        self.assertTrue(r["human_origin_declaration_required_not_cryptographically_verified"])
        self.assertTrue(r["public_https_source_url_required_content_not_verifiably_rechecked"])

    def test_no_human_network_or_registration_claim_from_green_ci(self):
        r=self.report
        self.assertTrue(all(x==0 for x in r["zero_claims"].values()))
        self.assertTrue(all(x is True for x in r["still_required"].values()))
        self.assertTrue(r["shipped"]["local_private_output_with_gitignore_protection"])


if __name__=="__main__":
    unittest.main()
