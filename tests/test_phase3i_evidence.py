"""Permanent audit of actual Phase 3I CI and research-only security evidence."""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class Phase3IRecordedRuntimeEvidence(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3i-2026-11-02.json").read_text())

    def test_source_patch_provenance_and_real_run(self):
        e=self.e
        self.assertEqual(e["schema_version"],1)
        self.assertEqual(e["status"],"PHASE3I_REAL_INSTALLED_REQUESTS_PROXY_AUTH_BOUNDARY_VERIFIED_RESEARCH_ONLY")
        self.assertEqual(e["verification"],"success")
        self.assertEqual(e["verified_workflow_url"],"https://github.com/Iniwura/falsum/actions/runs/41410209502")
        self.assertEqual(e["merged_pr_url"],"https://github.com/Iniwura/falsum/pull/6")
        self.assertEqual(e["case"]["fix_commit"],"74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5")
        self.assertEqual(e["case"]["upstream_source_blob"],"dbcf2a7b0ee2898b72714b756e4b27fbbad4beab")
        self.assertEqual(e["case"]["upstream_regression_test_blob"],"b420c44d73cde0c2ab7e7aa0e5182b345436f718")

    def test_installed_real_library_differential_and_negative_controls(self):
        r=self.e["installed_runtime"]
        self.assertEqual((r["exact_affected_version"],r["exact_fixed_version"]),("2.30.0","2.31.0"))
        self.assertEqual(r["separate_exact_version_jobs_passed"],2)
        self.assertTrue(r["paired_cross_version_job_passed"])
        self.assertTrue(r["real_requests_session_rebuild_proxies_executed"])
        self.assertTrue(r["request_objects_generated_in_memory"])
        self.assertEqual(r["http_requests_sent"],0)
        self.assertEqual(r["network_sockets_opened"],0)
        self.assertEqual(r["real_proxy_credentials_used"],0)
        self.assertEqual(r["real_customer_apps_inspected"],0)
        self.assertEqual(r["observations"],{
            "https_credentialed_proxy":{"affected_header_present":True,"fixed_header_present":False},
            "http_credentialed_proxy":{"affected_header_present":True,"fixed_header_present":True},
            "https_anonymous_proxy":{"affected_header_present":False,"fixed_header_present":False},
            "https_without_proxy":{"affected_header_present":False,"fixed_header_present":False},
            "https_stale_header_without_proxy":{"affected_header_present":False,"fixed_header_present":False},
        })

    def test_no_promoted_training_rows_or_false_model_quality_claims(self):
        v=self.e["validation"]
        self.assertEqual(v["new_phase3i_adversarial_test_methods"],13)
        self.assertEqual(v["full_foundation_tests_python_versions"],["3.11","3.12","3.13"])
        self.assertEqual(v["official_telegraph_data_diagnostic_gate"],"success")
        self.assertEqual(v["independent_human_approved_labels"],0)
        self.assertEqual(v["accepted_anjoman_rows"],0)
        self.assertEqual(v["accepted_training_pairs"],0)
        self.assertFalse(v["real_model_scored_in_this_phase"])
        self.assertFalse(v["registered_evaluator"])
        self.assertFalse(v["network_eligible"])
        self.assertTrue(v["model_release_veto_remains"])
        self.assertEqual(v["previous_phase3d_context_reversal_success"],"0/2")


if __name__=="__main__":
    unittest.main()
