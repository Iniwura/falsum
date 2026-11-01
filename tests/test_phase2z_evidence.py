"""Permanent Phase 2Z real-framework evidence; no fabricated network/release assertions."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class Phase2ZRealFrameworkEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase2z-2026-11-01.json").read_text(encoding="utf-8"))

    def test_actual_ci_and_pinned_executable_sources(self):
        e=self.e
        self.assertEqual(e["actual_verified_run"],
                         "https://github.com/Iniwura/falsum/actions/runs/41290076124")
        self.assertEqual(e["artifact_id"],13077016302)
        self.assertEqual(e["installed_runtime_dependency"]["exact_version"],"3.10.11")
        self.assertEqual(e["advisory_fixed_release"],"3.9.2")
        self.assertTrue(e["source_verification"]["verifies_executable_bytes_before_import"])
        self.assertEqual(len(e["tested_source_fixture_git_blobs"]),4)
        self.assertTrue(all(len(value)==40 for value in e["tested_source_fixture_git_blobs"].values()))
        self.assertEqual(e["source_verification"]["arbitrary_user_app_modules_executed"],0)

    def test_real_loopback_events_and_dynamic_source_abstention(self):
        e=self.e
        actual=e["controlled_framework_checks"]
        self.assertEqual(actual["real_aiohttp_web_application_instantiated"],3)
        self.assertEqual(actual["real_aiohttp_static_routes_registered"],3)
        self.assertTrue(actual["http_connections_loopback_only"])
        self.assertEqual(actual["normal_public_asset_http_200"],3)
        self.assertEqual(actual["nonexistent_asset_http_404"],3)
        self.assertEqual(actual["real_loopback_http_requests"],6)
        self.assertEqual(actual["external_network_requests"],0)
        self.assertEqual(actual["actual_route_follow_symlinks_values"],[False,True,False])
        self.assertEqual(actual["static_source_syntax_predictions"],
                         ["SYNTACTIC_ABSENT","SYNTACTIC_PRESENT","UNDETERMINED"])
        self.assertEqual(actual["runtime_resolves_dynamic_setting_while_static_analyzer_abstains"],1)
        self.assertEqual(e["ci_tests"]["total_focused_tests_passed"],58)
        self.assertEqual(e["ci_tests"]["ci_status"],"success")

    def test_dont_call_this_cve_or_independent_accuracy(self):
        x=self.e["limitations"]
        self.assertFalse(x["historically_vulnerable_release_executed"])
        self.assertFalse(x["historic_CVE_reproduction_attempted"])
        self.assertFalse(x["real_model_accuracy_measured"])
        self.assertFalse(x["network_eligible"])
        self.assertFalse(x["network_submission_authorized"])
        self.assertFalse(x["registered_evaluator"])
        for key in ("external_third_party_apps_tested","production_customer_apps_tested",
                    "confirmed_security_exploits","independent_human_ground_truth_labels",
                    "accepted_Anjoman_network_evaluation_rows"):
            self.assertEqual(x[key],0)
        self.assertFalse(self.e["installed_runtime_dependency"]["full_transitive_dependency_hash_lock"])


if __name__=="__main__":
    unittest.main()
