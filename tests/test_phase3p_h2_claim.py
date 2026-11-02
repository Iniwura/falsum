"""Protect the difference between a posted bounty claim and verified acceptance.

Offline checks use public-only, minimal metadata. They never inspect or
commit hidden eval-pool questions, answers, row hashes or wallet details.
"""
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]


class Phase3PPublicClaimAccuracy(unittest.TestCase):
    def setUp(self):
        self.p=json.loads((ROOT/"evidence/phase3p-2026-11-02-bounty-claim.json").read_text())

    def test_real_exact_public_bounty_receipt(self):
        r=self.p
        self.assertEqual(r["status"],"PHASE3P_PUBLIC_BOUNTY_SUBMIT_POSTED_PENDING_MAINTAINER_REVIEW")
        self.assertEqual(r["submission_comment_id"],6588168396)
        self.assertEqual(r["comment_author"],"Iniwura")
        self.assertEqual(r["posted_at_utc"],"2026-11-02T20:52:18Z")
        self.assertEqual(r["public_submission_url"],
                         "https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396")
        self.assertEqual(r["deliverable"],"Evaluation material contribution only")
        self.assertEqual(r["target_intent"],"SECURITY_REVIEW_GENERAL")

    def test_eligible_evidence_not_bounty_approval(self):
        r=self.p
        self.assertEqual(r["user_ui_reported_eligible_rows"],20)
        self.assertEqual(r["bounty_acceptance"],"PENDING_NOT_YET_INDEPENDENTLY_VERIFIED")
        self.assertTrue(r["bounty_issue_open_at_verification"])
        self.assertFalse(r["maintainer_acceptance_seen_after_submit"])
        self.assertFalse(r["evaluator_adapter_registered"])
        self.assertFalse(r["season_two_hackathon_entry_submitted"])
        self.assertFalse(r["winner_verified"])

    def test_private_network_material_not_published_by_record(self):
        r=self.p
        p=r["privacy"]
        self.assertFalse(p["private_eval_questions_published"])
        self.assertFalse(p["private_answer_keys_published"])
        self.assertFalse(p["private_row_hashes_published"])
        self.assertFalse(p["contributor_wallet_repeated_in_repository"])
        self.assertNotIn("0x9cBA6Cf",json.dumps(r))

    def test_h2_judge_instructions_and_script_exist(self):
        instructions=(ROOT/"docs/H2_EVALUATORS_JUDGE_PACK.md").read_text()
        shooting=(ROOT/"docs/H2_EVALUATORS_DEMO_STORYBOARD.md").read_text()
        self.assertIn("December",instructions)
        self.assertIn("0/3",instructions)
        self.assertIn("real",shooting)
        self.assertIn("2–5 minute",shooting)
        self.assertNotIn("0x9cBA6Cf",instructions+shooting)


if __name__=="__main__":
    unittest.main()
