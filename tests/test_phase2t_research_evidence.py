"""Prevent Phase 2T external-source diagnostic evidence from becoming false release claims."""
import json
import math
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PATH=ROOT/"evidence/phase2t-2026-10-31.json"


class Phase2TEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.d=json.loads(PATH.read_text(encoding="utf-8"))

    def test_reproduced_four_external_projects_never_flip_preferences(self):
        d=self.d
        x=d["new_model_diagnostic"]
        self.assertEqual(x["research_cases"],8)
        self.assertEqual(x["actual_model_inferences"],24)
        self.assertEqual(x["agreement_with_ai_proposed_judgments"],4)
        self.assertEqual(x["distinct_source_context_families"],4)
        self.assertEqual(x["families_agreeing_with_both_ai_proposed_context_preferences"],0)
        self.assertEqual(x["largest_full_modernbert_render_tokens"],466)
        self.assertEqual(x["model_cap"],512)
        self.assertEqual(len(x["projects"]),4)
        for row in x["projects"]:
            self.assertEqual(len(row["provisional_margins"]),2)
            a,b=row["provisional_margins"]
            self.assertTrue(math.isfinite(a) and math.isfinite(b))
            self.assertEqual(a>0,row["agreed_on_exposure"])
            self.assertEqual(b>0,row["agreed_on_missing_precondition"])
            self.assertEqual(sum((a>0,b>0)),1)
        self.assertFalse(d["approval"]["untouched_holdout"])
        self.assertFalse(d["approval"]["independent_model_accuracy_evaluated"])
        self.assertFalse(d["approval"]["training_authorized"])
        self.assertFalse(d["approval"]["network_eligible"])
        self.assertFalse(d["approval"]["telegraph_registered"])
        self.assertEqual(d["approval"]["human_expert_reviewed_pairs"],0)

    def test_prior_model_exposure_is_not_hidden(self):
        p=self.d["prior_model_advisory_exposure"]
        self.assertEqual(p["prior_ghsa_records"],32)
        self.assertEqual(p["new_cases_exact_prior_ghsa_count"],0)
        self.assertEqual(p["new_cases_prior_package_matches"],0)
        self.assertEqual(p["earlier_inspected_cases_exact_prior_ghsa_count"],2)
        self.assertEqual({x["advisory"] for x in p["earlier_inspected_exact_overlaps"]},
                         {"GHSA-cpwx-vrp4-4pq7","GHSA-jr5f-v2jv-69x6"})
        self.assertTrue(all(x["prior_split"]=="train" for x in p["earlier_inspected_exact_overlaps"]))
        self.assertIn("does not prove",p["interpretation"])

    def test_sha_pins_and_actual_run_ids(self):
        src=self.d["source_runs"]
        self.assertEqual(src["source_replay"],
                         "https://github.com/Iniwura/falsum/actions/runs/41232688735")
        self.assertEqual(src["frozen_model_score"],
                         "https://github.com/Iniwura/falsum/actions/runs/41232475893")
        self.assertEqual(src["source_model_score_artifact_id"],13053679923)
        for f in ("raw_model_report_sha256","source_model_adapter_sha256",
                  "model_question_packet_sha256"):
            self.assertRegex(src[f],r"^[a-f0-9]{64}$")
        self.assertEqual(self.d["source_inventory"]["distinct_repositories_total"],8)
        self.assertEqual(self.d["source_inventory"]["exact_source_and_test_replays"],8)


if __name__=="__main__":
    unittest.main()
