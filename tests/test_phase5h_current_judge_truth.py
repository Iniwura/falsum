"""Public judge-claim integrity tests. Offline source proof, not live network test.

Phase5G's separate real main-push HTTPS gate is the *only* source proving
that live Vercel serves the exact five-stage content. These checks only keep
README/judge docs consistent with that authenticated original release record.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from falsum import phase4v_real_source_witness_site as source
from falsum import phase5e_production_freshness as release
from falsum import phase5f_evaluator_scorecard as scorecard

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
JUDGE = ROOT / "docs/H2_EVALUATORS_JUDGE_PACK.md"
AUDIT = ROOT / "docs/H2_NOV20_FIRST_PLACE_READINESS_AUDIT.md"
OLD_GATE = ROOT / "docs/H2_NOV19_RULES_AND_SUBMISSION_GATE.md"

REAL_MAIN = "02c975df2000ef7b2f95ebbee60eb1a548b260b1"
REAL_LIVE_RUN = "https://github.com/Iniwura/falsum/actions/runs/44696464449"
REAL_SOURCE_SHA = "f77d00ffbe75d5d06cc233a56d066d74acf8a8c42ad2c0065ef1684157d82f6b"
REAL_DEPLOYMENT = "dpl_EHhg56Jjg8yWRpxLq7Ns87mgLD6A"
REAL_ARTIFACT_ID = "14610009413"


class CurrentPublicJudgeEvidenceAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = README.read_text(encoding="utf-8")
        cls.judge = JUDGE.read_text(encoding="utf-8")
        cls.audit = AUDIT.read_text(encoding="utf-8")
        cls.old = OLD_GATE.read_text(encoding="utf-8")

    def test_current_readme_cannot_revert_to_known_stale_quota_banner(self):
        top = self.readme.split("## Try the real upstream verification lab", 1)[0]
        self.assertIn("Public release: verified five-source workbench", top)
        self.assertIn("phase5e-live-production-source-freshness.yml", top)
        self.assertIn(REAL_LIVE_RUN, top)
        self.assertIn("https://github.com/Iniwura/falsum/actions/runs/44697989518", top)
        self.assertNotIn("dpl_", top)
        self.assertIn("Source content integrity", top)
        self.assertNotIn("still serves an older four-case commit", top)
        self.assertNotIn("remain open", top)
        self.assertNotIn("Do not claim the fifth case is live", top)

    def test_live_actions_proof_and_its_github_digest_are_documented_with_limits(self):
        for marker in (
            REAL_MAIN, REAL_DEPLOYMENT, REAL_LIVE_RUN, REAL_ARTIFACT_ID,
            REAL_SOURCE_SHA, "10 SUPPORTED", "10 CONTRADICTED", "60 ABSTAIN",
            "NOT SUBMITTED", "not independent", "not registered",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker.casefold(), self.audit.casefold())

    def test_judge_guide_current_summary_precedes_archived_64_case_story(self):
        self.assertIn("Current evidence — use this first (November 20)", self.judge)
        summary, old_body = self.judge.split("## What is FALSUM?", 1)
        self.assertIn(REAL_LIVE_RUN, summary)
        self.assertIn(REAL_MAIN, summary)
        self.assertIn(REAL_DEPLOYMENT, summary)
        self.assertIn("80 deterministic constructed browser decisions", summary)
        self.assertIn("historical four-case figures", summary)
        self.assertIn("not trained-model accuracy", summary)
        self.assertIn("NOT filed", summary)
        self.assertIn("64 deterministic", old_body)

    def test_historical_submissions_gate_is_explicitly_not_todays_release_state(self):
        start = self.old.split("## What is actually verified", 1)[0]
        self.assertIn("Historical checkpoint (November 19)", start)
        self.assertIn("H2_NOV20_FIRST_PLACE_READINESS_AUDIT.md", start)
        self.assertIn("currently working five-case/80-choice site", start)

    def test_actual_local_source_reference_matches_previously_real_live_proof_hash(self):
        # This establishes source hash compatibility with the PREVIOUS authentic
        # published GitHub main workflow, not a synthetic new live attestation.
        witness = source.assemble(ROOT)
        self.assertEqual(witness["source_fix_stage_count"],5)
        self.assertEqual(witness["upstream_project_count"],4)
        self.assertEqual(witness["precomputed_python_evaluations"],80)
        self.assertEqual(witness["by_construction_verdict_counts"],{
            "SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":60,
        })
        self.assertEqual(release.digest(release.canonical(witness)),REAL_SOURCE_SHA)
        self.assertFalse(witness["trained_model_improvement_proven"])
        self.assertFalse(witness["network_evaluator_registered"])
        self.assertEqual(witness["independent_appsec_expert_gold_labels"],0)

    def test_source_candidate_scorecard_is_open_book_and_constant_abstain_is_not_success(self):
        challenge,answers,_=scorecard.construct(ROOT)
        baseline = scorecard.score(
            challenge, answers, scorecard.baseline_predictions(challenge,"always-abstain"),
            origin="SYNTHETIC_CONSTANT_BASELINE")
        self.assertEqual(challenge["source_fix_stages"],5)
        self.assertFalse(challenge["blind_holdout"])
        self.assertFalse(challenge["answer_labels_in_challenge"])
        self.assertEqual(baseline["exact_matches"],60)
        self.assertEqual(baseline["raw_exact_match_ratio"],0.75)
        self.assertEqual(baseline["macro_class_recall"],0.333333)
        self.assertEqual(baseline["fully_correct_parent_fix_reversals"],0)
        self.assertEqual(baseline["independently_certified_human_appsec_gold_labels"],0)
        self.assertFalse(baseline["trained_model_performance_improvement_claimed"])

    def test_critical_external_owner_milestones_not_marked_as_completed(self):
        for marker in (
            "do not start demo", "official H2 entry", "independent",
            "unverified", "bounties", "registration",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker.casefold(), self.audit.casefold())
        self.assertNotIn("H2 final entry: SUBMITTED", self.audit)
        self.assertNotIn("independently verified human gold = 5", self.audit)


if __name__ == "__main__":
    unittest.main()
