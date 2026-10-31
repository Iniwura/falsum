"""Permanent AI research metric integrity checks: never turn drafts into truth."""
import json
import math
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/"evidence/ai-review-frozen-model-case-scores-2026-10-31.json"
SUMMARY=ROOT/"evidence/ai-review-phase2s-2026-10-31.json"


class AIReviewEvidenceTests(unittest.TestCase):
    def test_actual_case_scores_are_consistent_but_not_expert_accuracy(self):
        d=json.loads(REPORT.read_text(encoding="utf-8"))
        s=json.loads(SUMMARY.read_text(encoding="utf-8"))
        rows=d["case_scores"]
        self.assertEqual(len(rows),8)
        self.assertEqual(len({r["case_id"] for r in rows}),8)
        self.assertEqual({r["project"] for r in rows},{r["source_case"] if "source_case" in r else r["project"] for r in rows})
        self.assertEqual(d["metrics"]["ai_draft_agreements"],sum(r["agrees_with_ai_proposal"] for r in rows))
        self.assertEqual(d["metrics"]["ai_draft_agreements"],4)
        self.assertEqual(d["metrics"]["context_families_matching_both_ai_preferences"],0)
        self.assertEqual(d["metrics"]["model_inferences"],24)
        for row in rows:
            self.assertTrue(all(math.isfinite(row[k]) for k in (
                "score_a","score_b","ai_proposed_margin","answer_only_margin")))
            self.assertAlmostEqual(abs(row["score_a"]-row["score_b"]),
                                   abs(row["ai_proposed_margin"]),places=10)
            self.assertIs(row["agrees_with_ai_proposal"],row["ai_proposed_margin"]>0)
        for family in d["project_preferences"]:
            pair=[r for r in rows if r["project"]==family["project"]]
            self.assertEqual(len(pair),2)
            self.assertEqual({r["scenario"] for r in pair},{"exposure","missing-precondition"})
            self.assertEqual(sum(r["agrees_with_ai_proposal"] for r in pair),1)
            self.assertIn(family["selected_answer_kind_both_contexts"],("finding","conditional"))
        self.assertFalse(d["release"]["model_quality_validated"])
        self.assertFalse(d["release"]["network_eligible"])
        self.assertFalse(d["release"]["network_registered"])
        self.assertEqual(s["frozen_real_model_probe"]["model_agrees_with_ai_proposals"],4)
        self.assertEqual(s["frozen_real_model_probe"]["families_matching_both_ai_proposals"],0)

    def test_provenance_is_pinned_without_false_labels(self):
        d=json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(d["source_run"],"https://github.com/Iniwura/falsum/actions/runs/41211098910")
        for field in ("original_report_sha256","original_report_archive_sha256",
                      "actual_model_adapter_sha256","source_public_packet_sha256"):
            self.assertRegex(d[field],r"^[0-9a-f]{64}$")
        self.assertEqual(d["metrics"]["human_expert_reviews"],0)
        self.assertEqual(d["metrics"]["anjoman_eligible_pairs"],0)
        self.assertIs(d["release"]["model_training_authorized_for_submission"],False)


if __name__=="__main__":
    unittest.main()
