"""Permanent phase 3A real upstream source provenance cannot become exploit 'accuracy'."""
import json
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


class ExternalAppEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3a-2026-11-01.json").read_text())

    def test_pinned_external_projects_and_five_authentic_call_sites(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE3A_THREE_AUTHENTIC_EXTERNAL_APP_FILES_VERIFIED_SOURCE_ONLY")
        self.assertEqual(e["ci_run"],"https://github.com/Iniwura/falsum/actions/runs/41290675846")
        self.assertEqual(e["artifact_id"],13076967118)
        self.assertEqual(e["source_verification"]["unique_outside_project_repositories"],3)
        self.assertEqual(e["source_verification"]["exact_git_blob_bytes_verified"],3)
        self.assertEqual(e["source_verification"]["source_call_sites"],5)
        self.assertEqual(e["source_verification"]["explicit_true"],1)
        self.assertEqual(e["source_verification"]["explicit_false"],2)
        self.assertEqual(e["source_verification"]["omitted_option_unresolved"],2)
        self.assertEqual(len(e["studies"]),3)
        self.assertEqual(len({r["repository"] for r in e["studies"]}),3)
        for source in e["studies"]:
            self.assertEqual(len(source["commit"]),40)
            self.assertEqual(len(source["expected_git_blob_sha1"]),40)
            self.assertTrue(all(x["syntax"] in ("EXPLICIT_TRUE","EXPLICIT_FALSE","OMITTED_OPTION")
                                for x in source["calls"]))
        self.assertEqual(sum(len(r["calls"]) for r in e["studies"]),5)

    def test_33_execution_gates_passed_but_not_external_application_runtime(self):
        e=self.e
        c=e["tests"]
        self.assertEqual(c["phase3a_adversarial_offline"],15)
        self.assertEqual(c["phase2z_runtime_contract"],15)
        self.assertEqual(c["phase2z_evidence_integrity"],3)
        self.assertEqual(c["total_focused"],33)
        self.assertEqual(c["initial_external_source_ci_conclusion"],"success")
        self.assertEqual(c["foundation_workflow_conclusion"],"success")
        self.assertEqual(c["official_diagnostic_data_gate_conclusion"],"success")

    def test_no_fabricated_version_label_vulnerability_or_network_release(self):
        e=self.e
        for f in ("affected_dependency_versions_ascertained","real_external_application_executed",
                  "full_third_party_application_audited","external_app_reachability_proven",
                  "live_telegraph_evaluator_registered","network_eligible"):
            self.assertFalse(e["trust_boundary"][f])
        for f in ("external_app_vulnerability_confirmed",
                  "independent_appsec_human_labels",
                  "accepted_anjoman_evaluation_rows"):
            self.assertEqual(e["trust_boundary"][f],0)
        self.assertTrue(e["trust_boundary"]["no_user_code_execution_authorized"])
        self.assertFalse(e["source_verification"]["code_under_review_imported_or_executed"])


if __name__=="__main__":
    unittest.main()
