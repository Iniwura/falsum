"""Season II public entry gate: provenance before submission, no false approvals.

These are fail-closed assertions about an internally prepared competition
submission pack. They CANNOT check private registration, actual signed-in
GitHub stars, publication actions, expert independence or H2 submission.
"""
from __future__ import annotations

from pathlib import Path
import unittest

from falsum.phase4v_real_source_witness_site import assemble as build_real_source_proof

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "docs/H2_NOV19_RULES_AND_SUBMISSION_GATE.md"
ENTRY = ROOT / "docs/H2_FINAL_ENTRY_DRAFT.md"
README = ROOT / "README.md"


def inspect(draft: str, entry: str, readme: str) -> dict:
    if not draft.startswith("# FALSUM — Season II submission evidence gate"):
        raise ValueError("missing season II official evidence gate")
    expected = (
        "https://hackathon.telegraphprotocol.com/rules",
        "Evaluators",
        "SECURITY_REVIEW_GENERAL",
        "December 1, 2026, 23:59 UTC",
        "NOT SUBMITTED",
        "20 total, 20 Eligible",
        "https://github.com/Iniwura/falsum/actions/runs/44311491808",
        "https://github.com/Iniwura/falsum/actions/runs/44356563508",
        "5/8",
        "1/4",
        "4/8",
        "ZERO confirmed",
        "Star the bounties repository",
        "2–5 minute video or accessible equivalent",
        "NO THREE VERIFIED PUBLIC URLs",
        "NOT FORMALLY CONFIRMED",
        "not a completed independent review",
        "no new independent expert labels",
        "https://hackathon.telegraphprotocol.com/missions/model-economy",
        "not independently proved",
        "drafts are **not** credited as actual posts",
        "no paid Telegraph requests",
    )
    low = draft.lower()
    for item in expected:
        if item.lower() not in low:
            raise ValueError("public entry precondition missing or misrepresented: " + item[:75])
    if "**Submission state: NOT SUBMITTED." not in draft:
        raise ValueError("official competition has no submission receipt")
    if "**STATUS: NOT SUBMITTED.**" not in entry:
        raise ValueError("final H2 entry falsely promoted")
    if "maintainer acceptance remains unresolved" not in entry.lower():
        raise ValueError("bounty acceptance cannot be inferred from Eligible status")
    if "H2_NOV19_RULES_AND_SUBMISSION_GATE.md" not in readme:
        raise ValueError("judge cannot find precise official compliance gate")
    if "https://falsum-evidence-lab.vercel.app/witness/" not in draft:
        raise ValueError("working source witness not identified")
    if "official entry" not in draft.lower():
        raise ValueError("GitHub bounty comment must not be confused with official entry")
    for phrase in (
        "DO NOT CLAIM WINNER", "20 trained-model improvements", "FALSUM is certified",
        "independent gold approved", "accepted by judges", "Hackathon submission completed",
    ):
        if phrase.lower() in low:
            raise ValueError("fabricated winning or expert outcome")
    if draft.count("**A · The problem") != 1 or draft.count("**B · New reproducible") != 1 or draft.count("**C · Invite") != 1:
        raise ValueError("three distinct technical update drafts required")
    if draft.count("unpublished draft") != 3:
        raise ValueError("drafts must never be presented as posted")
    return {
        "official_h2_entry_filed": False,
        "registered_email_form_is_season_ii_receipt": False,
        "github_bounties_star_independently_verified": False,
        "three_original_progress_posts_with_real_urls_confirmed": False,
        "external_appsec_human_gold_verified": 0,
        "demo_or_accessible_equivalent_submitted": False,
        "operator_permission_to_share_public_assets_verified": False,
        "recorded_executable_source_fix_stages": 4,
        "recorded_source_review_verdicts": 64,
        "original_lora_improvement_proven": False,
        "judge_instructions_and_bounded_evidence_documented": True,
        "submission_complete": False,
        "notice": "Technical proof and owner-only eligibility, permission and publication steps are separate. Public drafts and green CI are not receipts.",
    }


class OfficialSeason2ReleaseEvidenceGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = RULES.read_text(encoding="utf-8")
        cls.entry = ENTRY.read_text(encoding="utf-8")
        cls.readme = README.read_text(encoding="utf-8")

    def test_current_official_rules_and_owner_uncertainty_are_distinct(self):
        result = inspect(self.text, self.entry, self.readme)
        self.assertFalse(result["official_h2_entry_filed"])
        self.assertFalse(result["registered_email_form_is_season_ii_receipt"])
        self.assertFalse(result["github_bounties_star_independently_verified"])
        self.assertFalse(result["three_original_progress_posts_with_real_urls_confirmed"])
        self.assertFalse(result["submission_complete"])
        self.assertFalse(result["operator_permission_to_share_public_assets_verified"])

    def test_genuine_four_stage_source_bundle_is_independent_of_unsubmitted_competition(self):
        report = build_real_source_proof()
        status = inspect(self.text, self.entry, self.readme)
        self.assertEqual(report["source_fix_stage_count"],status["recorded_executable_source_fix_stages"])
        self.assertEqual(report["precomputed_python_evaluations"],status["recorded_source_review_verdicts"])
        self.assertEqual(report["upstream_project_count"],3)
        self.assertEqual(report["independent_appsec_expert_gold_labels"],0)
        self.assertFalse(report["trained_model_improvement_proven"])
        self.assertFalse(report["official_h2_submission_confirmed"])

    def test_fake_submission_or_registered_evaluator_cannot_pass(self):
        for original, replacement in (
            ("**Submission state: NOT SUBMITTED.", "**Submission state: SUBMITTED."),
            ("**ZERO confirmed**", "**ONE verified**"),
            ("**UNKNOWN**", "**VERIFIED**"),
            ("**NO THREE VERIFIED PUBLIC URLs**", "**ALL POSTS VERIFIED**"),
            ("**NOT FORMALLY CONFIRMED**", "**CONFIRMED**"),
        ):
            if original not in self.text:
                continue
            with self.subTest(original=original),self.assertRaises(ValueError):
                inspect(self.text.replace(original,replacement),self.entry,self.readme)

    def test_public_update_drafts_cannot_be_misrepresented_as_real_posts(self):
        with self.assertRaisesRegex(ValueError,"drafts must never"):
            inspect(self.text.replace("unpublished draft", "posted"),self.entry,self.readme)

    def test_owner_star_requirement_cannot_be_hidden(self):
        with self.assertRaisesRegex(ValueError,"Star the bounties repository"):
            inspect(self.text.replace("Star the bounties repository","Ignore the official GitHub requirement"),
                    self.entry,self.readme)

    def test_unsupported_registration_statement_cannot_replace_actual_pending_state(self):
        with self.assertRaisesRegex(ValueError,"NOT FORMALLY CONFIRMED"):
            inspect(self.text.replace("NOT FORMALLY CONFIRMED","OFFICIALLY ACCEPTED"),self.entry,self.readme)

    def test_public_statement_does_not_rewrite_observed_model_failures(self):
        for failure in ("5/8","1/4","4/8"):
            with self.subTest(failure=failure),self.assertRaises(ValueError):
                inspect(self.text.replace(failure,"100% success"),self.entry,self.readme)

    def test_submission_doc_links_have_real_repository_targets(self):
        from urllib.parse import urlparse
        import re
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)",self.text):
            if target.startswith(("http://","https://")):
                self.assertIn(urlparse(target).scheme,("http","https"))
            elif not target.startswith("#"):
                with self.subTest(target=target):
                    dest=(RULES.parent/target.split("#")[0]).resolve()
                    self.assertTrue(dest.is_relative_to(ROOT))
                    self.assertTrue(dest.is_file(), target)


if __name__ == "__main__":
    unittest.main()
