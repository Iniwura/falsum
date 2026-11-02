"""Phase 3G: adversarial public GitHub reviewer intake tests, no expert-label promotion."""
import hashlib
import json
import unittest

from falsum.phase3f_multifamily_material import PINS, STATUS as OLD_STATUS
from falsum.phase3g_public_review import (
    STATUS, ISSUE_API, ISSUE_WEB, ReviewError, check_bundle,
    blank_templates, ingest, sha,
)


def fixture():
    rows = []
    for ident, repo, commit, src, test in PINS:
        source_file = "example/security.py"
        test_file = "tests/security_test.py"
        rows.append({
            "packet_id": ident, "repository": repo, "fix_commit": commit,
            "source_post_fix_git_blob_sha1": src,
            "regression_test_post_fix_git_blob_sha1": test,
            "source_patch_sha256": "a"*64, "regression_test_patch_sha256": "b"*64,
            "source_file": source_file, "regression_test_file": test_file,
            "source_url": f"https://github.com/{repo}/blob/{commit}/{source_file}",
            "test_url": f"https://github.com/{repo}/blob/{commit}/{test_file}",
            "unreviewed_candidates": [
                {"id": k, "text": t, "sha256": hashlib.sha256(t.encode()).hexdigest()}
                for k, t in [("A", "Answer A with some caution"), ("B", "Answer B, an overconfident answer")]
            ],
            "human_preference": None, "human_review_verified": False,
            "candidate_order_human_randomized": False,
            "source_patch_is_exploit_proof": False,
            "production_app_version_known": False,
            "production_traffic_exposure_known": False,
            "training_authorized": False, "network_eligible": False,
            "label_status": "AUTHOR_DRAFT_WITH_REAL_SOURCE_NOT_ADJUDICATED",
        })
    return {
        "schema_version": 1, "status": OLD_STATUS, "review_cases": 7,
        "distinct_security_families": 7,
        "external_source_and_test_file_blob_pairs_verified": 8,
        "fresh_project_holdout_reused": False,
        "research_only": True, "independent_human_labels": 0,
        "accepted_training_pairs": 0, "network_eligible": False,
        "registered_evaluator": False, "review_packets": rows,
    }


def make_comment(bundle, cid=14, uid=80, login="external-auditor", preference="A"):
    p = bundle["review_packets"][0]
    payload = {
        "schema_version": 1,
        "packet_bundle_sha256": sha(bundle),
        "packet_id": p["packet_id"],
        "candidate_answer_sha256": [a["sha256"] for a in p["unreviewed_candidates"]],
        "preference": preference,
        "source_url": p["source_url"], "test_url": p["test_url"],
        "reasoning": "I checked the source and upstream regression test, but the deployment preconditions still require independent validation.",
        "unresolved_facts": "Deployed version, reachable entry point, effective configuration and attacker-controlled input remain unknown.",
    }
    return {
        "id": cid, "html_url": f"{ISSUE_WEB}#issuecomment-{cid}",
        "issue_url": ISSUE_API, "user": {"id": uid, "type": "User", "login": login},
        "body": "Evidence:\n```falsum-review-v1\n" + json.dumps(payload) + "\n```",
    }


class PublicReviewTests(unittest.TestCase):
    def test_seven_pinned_packets_and_zero_labels(self):
        b = fixture()
        self.assertEqual(len(check_bundle(b)), 7)
        out = ingest(b, [[]])
        self.assertEqual(out["status"], STATUS)
        self.assertEqual(out["structured_review_claims"], 0)
        self.assertEqual(out["independently_verified_expert_labels"], 0)
        self.assertEqual(out["accepted_training_pairs"], 0)
        self.assertFalse(out["network_eligible"])
        self.assertFalse(out["github_comments_retrieved_via_https"])

    def test_blank_templates_are_bound_and_not_labels(self):
        b = fixture(); t = blank_templates(b)
        self.assertEqual(len(t["examples"]), 7)
        self.assertIn(sha(b), t["examples"][0]["github_comment_markdown"])
        self.assertIn("REPLACE WITH", t["examples"][0]["github_comment_markdown"])

    def test_offline_snapshot_cannot_claim_github_attribution(self):
        b = fixture(); out = ingest(b, [[make_comment(b)]])
        self.assertEqual(out["structured_review_claims"], 1)
        self.assertFalse(out["claims"][0]["github_attribution_checked_via_api"])
        self.assertFalse(out["claims"][0]["appsec_expertise_verified"])
        self.assertFalse(out["claims"][0]["independent_reviewer_verified"])
        self.assertFalse(out["claims"][0]["training_eligible"])

    def test_github_transport_does_not_verify_correctness(self):
        b = fixture()
        out = ingest(b, [[make_comment(b)]], github_api_fetched=True)
        self.assertTrue(out["claims"][0]["github_attribution_checked_via_api"])
        self.assertFalse(out["claims"][0]["underlying_security_claims_verified"])
        self.assertEqual(out["independently_verified_expert_labels"], 0)

    def test_pins_and_forced_promotion_rejected(self):
        for key, value in (
            ("source_post_fix_git_blob_sha1", "f"*40),
            ("regression_test_post_fix_git_blob_sha1", "0"*40),
            ("human_preference", "A"),
            ("training_authorized", True),
            ("source_url", "https://somewhere.example/src"),
            ("label_status", "EXPERT_APPROVED"),
        ):
            with self.subTest(field=key):
                b = fixture(); b["review_packets"][0][key] = value
                with self.assertRaises(ReviewError): check_bundle(b)

    def test_modified_answer_text_rejected(self):
        b = fixture()
        b["review_packets"][0]["unreviewed_candidates"][0]["text"] = "tampered"
        with self.assertRaises(ReviewError): blank_templates(b)

    def test_changing_preference_never_grants_label(self):
        b = fixture(); c = make_comment(b)
        c["body"] = c["body"].replace('"preference": "A"', '"preference": "B"')
        out = ingest(b, [[c]], github_api_fetched=True)
        self.assertEqual(out["claims"][0]["preference_claim"], "B")
        self.assertEqual(out["accepted_training_pairs"], 0)

    def test_wrong_bundle_and_answer_hash_rejected(self):
        b = fixture()
        for old, new in (
            (sha(b), "0"*64),
            (b["review_packets"][0]["unreviewed_candidates"][0]["sha256"], "1"*64),
        ):
            c = make_comment(b); c["body"] = c["body"].replace(old, new)
            out = ingest(b, [[c]])
            self.assertEqual(out["structured_review_claims"], 0)
            self.assertEqual(out["rejected_review_blocks"][0]["reason"], "stale_or_tampered_source_binding")

    def test_unedited_template_is_not_review(self):
        b = fixture(); c = make_comment(b)
        c["body"] = c["body"].replace(
            "I checked the source and upstream regression test, but the deployment preconditions still require independent validation.",
            "REPLACE WITH SOME INPUT TEXT THAT LOOKS LIKE REASONING",
        )
        self.assertEqual(ingest(b, [[c]])["structured_review_claims"], 0)

    def test_comment_identity_must_match_real_issue(self):
        b = fixture()
        for key, value in (
            ("html_url", "https://github.com/attacker/falsum/issues/3#issuecomment-14"),
            ("issue_url", "https://api.github.com/repos/attacker/falsum/issues/3"),
            ("id", -4),
        ):
            c = make_comment(b); c[key] = value
            with self.subTest(field=key), self.assertRaises(ReviewError):
                ingest(b, [[c]])

    def test_owner_and_bots_not_reviewers(self):
        b = fixture(); c = make_comment(b, login="Iniwura")
        out = ingest(b, [[c]])
        self.assertEqual(out["structured_review_claims"], 0)
        self.assertEqual(out["rejected_review_blocks"][0]["reason"], "project_owner_not_external")
        c = make_comment(b); c["user"]["type"] = "Bot"
        with self.assertRaises(ReviewError): ingest(b, [[c]])

    def test_duplicate_author_packet_quarantined(self):
        b = fixture()
        out = ingest(b, [[make_comment(b), make_comment(b, cid=15)]])
        self.assertEqual(out["duplicate_author_packet_groups"], 1)
        self.assertTrue(all(c["duplicate_review_for_packet"] for c in out["claims"]))
        self.assertEqual(out["claimed_preference_sets_excluding_duplicates"][b["review_packets"][0]["packet_id"]], [])

    def test_conflicting_reviewers_visible_without_promotion(self):
        b = fixture()
        a = make_comment(b)
        c = make_comment(b, cid=15, uid=81, login="different-reviewer", preference="B")
        out = ingest(b, [[a, c]], github_api_fetched=True)
        self.assertEqual(out["unresolved_A_B_disagreements"], 1)
        self.assertEqual(out["unique_nonowner_github_author_ids"], 2)
        self.assertEqual(out["independently_verified_expert_labels"], 0)

    def test_abstentions_remain_unresolved(self):
        b = fixture(); out = ingest(b, [[make_comment(b, preference="ABSTAIN")]])
        self.assertEqual(out["unresolved_abstentions"], 1)
        self.assertEqual(out["accepted_training_pairs"], 0)

    def test_duplicate_comment_ids_fail_closed(self):
        b = fixture(); c = make_comment(b)
        with self.assertRaises(ReviewError): ingest(b, [[c], [c]])

    def test_nonreview_discussion_not_miscounted(self):
        b = fixture(); c = make_comment(b); c["body"] = "General question."
        out = ingest(b, [[c]])
        self.assertEqual(out["structured_review_claims"], 0)
        self.assertEqual(out["rejected_review_blocks"], [])


if __name__ == "__main__":
    unittest.main()
