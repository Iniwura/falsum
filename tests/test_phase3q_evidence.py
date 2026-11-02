"""Public Phase 3Q CI-evidence ledger: keep real synthetic execution distinct from live integrations."""
from pathlib import Path
import json
import unittest


ROOT=Path(__file__).resolve().parents[1]


class Phase3QEvidence(unittest.TestCase):
    def setUp(self):
        self.e=json.loads((ROOT/"evidence/phase3q-2026-11-03.json").read_text())

    def test_exact_real_ci_and_pr(self):
        e=self.e
        self.assertEqual(e["status"],"PHASE3Q_REAL_EXECUTED_SYNTHETIC_PR_SECURITY_REVIEW_LAB_VERIFIED")
        self.assertEqual(e["merged_pr"],"https://github.com/Iniwura/falsum/pull/14")
        self.assertEqual(e["verified_ci"],"https://github.com/Iniwura/falsum/actions/runs/41547305623")
        self.assertEqual(e["workflow_conclusion"],"success")
        self.assertEqual(e["merge_sha"],"a2a03f6406d3cdf1674ccd37f9d25b55095f8da4")

    def test_real_local_execution_but_not_third_party_mission(self):
        m=self.e["verified_observations"]
        self.assertEqual(m["fictional_mission_workflows"],["EXCHANGE","MODEL ECONOMY","WEB3 NATIVE & DEFI"])
        self.assertEqual(m["real_executed_before_after_python_implementations"],6)
        self.assertEqual(m["unsafe_operations_reproduced_in_local_prepatch_fixtures"],3)
        self.assertEqual(m["unsafe_operations_blocked_in_local_postpatch_fixtures"],3)
        self.assertEqual(m["legitimate_operations_preserved_in_local_patched_fixtures"],3)
        self.assertEqual(m["synthetic_only_new_targeted_tests"],15)
        self.assertTrue(m["standalone_offline_html_demo_artifact"])
        self.assertEqual(m["passing_python_versions"],["3.11","3.12","3.13"])

    def test_no_promoted_ai_model_human_review_or_private_network_data(self):
        x=self.e["scope"]
        self.assertEqual(x["real_mission_partner_integrations_verified"],0)
        self.assertEqual(x["model_inferences_executed"],0)
        self.assertEqual(x["new_eligible_network_material_from_demo"],0)
        self.assertFalse(x["source_questions_from_private_evalpool_used"])
        self.assertEqual(x["independently_expert_approved_security_labels"],0)
        self.assertFalse(x["evaluator_adapter_live"])
        self.assertTrue(x["previous_20_eligible_rows_unchanged"])

    def test_judge_docs_reproduce_working_lab(self):
        lab=(ROOT/"docs/PHASE3Q.md").read_text()
        judge=(ROOT/"docs/H2_EVALUATORS_JUDGE_PACK.md").read_text()
        storyboard=(ROOT/"docs/H2_EVALUATORS_DEMO_STORYBOARD.md").read_text()
        target="python -m falsum.phase3q_mission_lab --out-dir"
        self.assertIn(target,lab)
        self.assertIn(target,judge)
        self.assertIn(target,storyboard)
        self.assertIn("synthetic",lab.lower())
        self.assertNotIn("0x9cBA6Cf",judge+lab+storyboard)


if __name__=="__main__":
    unittest.main()
