"""Prevent Phase 3H source-only/runtime comparison results becoming model or network claims."""
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StarletteRealRuntimeEvidence(unittest.TestCase):
    def setUp(self):
        self.e = json.loads((ROOT / "evidence/phase3h-2026-11-02.json").read_text())

    def test_provenance_is_pinned_to_passing_ci_and_original_patch(self):
        e = self.e
        self.assertEqual(e["schema_version"], 1)
        self.assertEqual(e["status"], "PHASE3H_REAL_INSTALLED_HISTORICAL_STARLETTE_RUNTIME_DELTA_VERIFIED_RESEARCH_ONLY")
        self.assertEqual(e["workflow_conclusion"], "success")
        self.assertEqual(e["successful_workflow_url"], "https://github.com/Iniwura/falsum/actions/runs/41409503521")
        self.assertEqual(e["merged_pr_url"], "https://github.com/Iniwura/falsum/pull/5")
        self.assertEqual(e["historical_case"]["upstream_security_fix_commit"],
                         "1797de464124b090f10cf570441e8292936d63e3")
        self.assertEqual(e["historical_case"]["original_upstream_source_blob"],
                         "4c856063c2945d93f1b79505f9d8de7919b947aa")
        self.assertEqual(e["historical_case"]["original_upstream_regression_test_blob"],
                         "23d0b57fc2b23fbc5f23734ce856980a3d4ae064")

    def test_real_installed_versions_and_four_isolated_observations(self):
        e = self.e
        rt = e["real_runtime"]
        self.assertEqual((rt["vulnerable_installed_version"], rt["patched_installed_version"]),
                         ("0.26.1", "0.27.0"))
        self.assertEqual(rt["separate_exact_version_install_jobs_passed"], 2)
        self.assertTrue(rt["cross_version_comparison_job_passed"])
        self.assertTrue(rt["synthetic_fixtures_only"])
        self.assertTrue(rt["in_process_calls_to_actual_Starlette_get_path_and_get_response"])
        self.assertFalse(rt["new_http_server_started"])
        self.assertEqual(rt["production_applications_tested"], 0)
        self.assertEqual(rt["private_user_files_read"], 0)
        self.assertEqual(rt["controls"], {
            "inside_file": {"vulnerable_http_status": 200, "patched_http_status": 200},
            "missing_file": {"vulnerable_http_status": 404, "patched_http_status": 404},
            "unrelated_sibling": {"vulnerable_http_status": 404, "patched_http_status": 404},
            "same_prefix_outside_root_sibling": {"vulnerable_http_status": 200, "patched_http_status": 404},
        })

    def test_current_model_still_quarantined(self):
        e = self.e
        v = e["verification"]
        self.assertEqual(v["focused_offline_adversarial_test_methods"], 16)
        self.assertEqual(v["framework_runtime_matrix_jobs_passed"], 2)
        self.assertTrue(v["cross_version_assertion_passed"])
        self.assertTrue(v["foundation_test_matrix_passed"])
        self.assertTrue(v["official_telegraph_diagnostic_gate_passed"])
        self.assertFalse(v["real_model_scored_in_phase"])
        self.assertFalse(v["model_retrained_in_phase"])
        self.assertEqual(v["independently_approved_appsec_labels"], 0)
        self.assertEqual(v["accepted_training_pairs"], 0)
        self.assertEqual(v["accepted_anjoman_evaluation_rows"], 0)
        self.assertFalse(v["registered_evaluator"])
        self.assertFalse(v["network_eligible"])
        self.assertTrue(v["model_release_veto_remains"])
        self.assertEqual(v["previous_phase3d_context_reversal_success"], "0/2")


if __name__ == "__main__":
    unittest.main()
