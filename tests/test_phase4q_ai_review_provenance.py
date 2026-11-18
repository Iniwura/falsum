"""Check that the publicly authored AI source audit is not human-gold evidence.

These guards test provenance disclosure, frozen citations and lack of implicit
label promotions. They do not validate a human review, security correctness,
any browser behavior or actual model quality.
"""
from pathlib import Path
import json
import re
import unittest

from falsum.phase4p_open_source_review import load_lock

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md"
LOCK = ROOT / "data/phase4p-three-project-open-review-lock.json"
README = ROOT / "README.md"


class AIAssistedSourceReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = DOC.read_text(encoding="utf-8")
        cls.lock = load_lock(LOCK.read_bytes())

    def test_source_audit_declares_ai_assistance_not_human_certification(self):
        text = self.report.lower()
        for required in (
            "ai-generated technical review",
            "not an independently hired",
            "not a separate human identity",
            "not a professional certification",
            "not source-independent gold",
            "same chatgpt-assisted build",
            "not a scored answer key",
            "not a sealed blind adjudication",
            "zero",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertIn("independently certified human experts (0)",text)
        self.assertIn("accepted gold preference labels (0)",text)

    def test_each_case_and_stage_has_pinned_source_and_test_evidence(self):
        for case in self.lock["cases"]:
            self.assertIn(case["id"].split("phase4p-")[1].split("-")[0].capitalize(),self.report)
            self.assertIn(case["advisory_url"],self.report)
            for stage in case["patches"]:
                for kind in ("source", "test"):
                    target=(
                        f"https://github.com/{case['repository']}/blob/"
                        f"{stage['fix']}/{stage[kind+'_path']}"
                    )
                    with self.subTest(case=case["id"],stage=stage["stage"],file=kind):
                        self.assertIn(target,self.report)
                        # The proof must point into a real immutable file line range.
                        suffix=self.report.split(target,1)[1]
                        self.assertTrue(suffix.startswith("#L"))

    def test_observations_are_scoped_and_negative_findings_preserved(self):
        text=self.report
        for signal in (
            "url.host === this.ctx.host",
            "not scheme",
            "resolved_path.suffix",
            "does **not** prove",
            "_load_examples",
            "app.request()",
            "not a real Chrome/Edge",
            "ABSTAIN",
            "any application-level redirect filters",
            "not an asserted new exploit",
            "unverified",
        ):
            with self.subTest(signal=signal):
                self.assertIn(signal.lower(),text.lower())

    def test_doc_is_outside_precommitted_source_lock_not_backfilled_as_label(self):
        lock=self.lock
        self.assertTrue(lock["no_answer_candidates_or_author_golden_verdicts"])
        self.assertTrue(lock["no_expert_labels"])
        self.assertTrue(lock["not_a_sealed_or_model_pretraining_blind_holdout"])
        self.assertFalse(lock["registered_evaluator"])
        for row in lock["cases"]:
            self.assertEqual(set(row), {
                "id","repository","advisory_url","security_family",
                "language","questions","patches"})
            self.assertNotIn("preferred_answer",row)
            self.assertNotIn("human_gold",row)
        # The AI memo must not alter the preceding Phase 4P public source lock.
        self.assertEqual(len(lock["cases"]),3)
        self.assertEqual(sum(len(x["patches"]) for x in lock["cases"]),4)

    def test_readme_provenance_link_and_no_claim_of_independent_human_verification(self):
        readme=README.read_text(encoding="utf-8")
        self.assertIn("PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md",readme)
        nearby=readme.split("PHASE4Q_AI_ADVERSARIAL_SOURCE_REVIEW.md",1)[0][-400:]
        self.assertIn("AI",nearby)
        self.assertIn("not",nearby.lower())
        self.assertIn("not independently verified human gold",nearby.lower())

    def test_no_model_scoring_or_real_eligible_pairs_in_self_audit(self):
        text=self.report.lower()
        self.assertIn("any new anjoman evaluation rows from this pack (0)",text)
        self.assertIn("none registered",text)
        self.assertIn("no private",text)
        self.assertNotIn("human review count: 3",text)
        self.assertNotIn("certified model accuracy",text)
        self.assertNotIn("training label approved",text)


if __name__=="__main__":
    unittest.main()
