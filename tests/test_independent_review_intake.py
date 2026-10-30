"""Offline adversarial tests for public review intake. No human labels fabricated."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.independent_review_intake import (
    ATTESTATIONS, HEADINGS, IntakeError, assemble, main, validate_claim,
)
from falsum.real_fix_corpus import load_queue

ROOT = Path(__file__).resolve().parents[1]


def make_issue(row, *, number=10, reviewer="reviewerAlpha", verdict="supported"):
    parent = f'https://github.com/{row["repository"]}/blob/{row["parent"]}/{row["source_path"]}#L1-L4'
    fixed = f'https://github.com/{row["repository"]}/blob/{row["commit"]}/{row["test_path"]}#L2-L10'
    parts = [
        row["id"],
        verdict,
        "The pre-fix code follows a caller-dependent data flow past a trust boundary. "
        "I inspected the exact source statements, the fix and associated regression test. "
        "A real deployment would need to expose the relevant path to an untrusted caller before this becomes an exploitable issue.",
        "Affected use depends on the runtime configuration, library revision and whether untrusted callers control the relevant input. "
        "The publication itself does not prove a live deployment has the same exposure.",
        f"Parent code at {parent}\nFixed test at {fixed}\nAuthoritative published advisory at {row['public_source']}. "
        "These precise lines show what changed and give a reproducible path to the evidence.",
        "A different upstream version or safe configuration might invalidate the claim. "
        "Before giving a definitive judgment I would reproduce the attack path and check relevant test coverage.",
        "\n".join("- [x] " + statement for statement in ATTESTATIONS),
    ]
    body = "\n\n".join("### " + heading + "\n\n" + value for heading, value in zip(HEADINGS, parts))
    return {
        "number": number, "title": f"[AppSec review] {row['id']}",
        "user": {"login": reviewer, "type": "User"},
        "html_url": f"https://github.com/Iniwura/falsum/issues/{number}",
        "state": "open", "created_at": "2026-10-30T10:00:00Z",
        "updated_at": "2026-10-30T10:01:00Z", "body": body,
    }


class IntakeTests(unittest.TestCase):
    def setUp(self):
        self.queue = load_queue(ROOT / "data/real-fix-queue.json")
        self.case = self.queue["cases"][0]
        self.rows = {r["id"]: r for r in self.queue["cases"]}

    def test_zero_real_review_claims_no_labels(self):
        report = assemble(self.queue, [])
        self.assertEqual(report["source_case_count"], 4)
        self.assertEqual(report["valid_format_claims"], 0)
        self.assertEqual(report["accepted_independent_expert_reviews"], 0)
        self.assertEqual(report["accepted_training_labels"], 0)
        self.assertEqual(report["exportable_preference_pairs"], [])
        self.assertFalse(report["network_eligible"])
        self.assertTrue(all(c["status"] == "NO_VALID_REVIEW_CLAIMS" for c in report["cases"]))

    def test_one_claim_is_not_independent_label(self):
        issue = make_issue(self.case)
        result = validate_claim(issue, self.rows)
        self.assertEqual(result["verdict_claim"], "supported")
        self.assertEqual(result["github_author_login"], "reviewerAlpha")
        self.assertFalse(result["technical_expertise_verified"])
        self.assertFalse(result["human_authorship_verified"])
        self.assertFalse(result["training_label_accepted"])
        report = assemble(self.queue, [issue])
        self.assertEqual(report["valid_format_claims"], 1)
        self.assertEqual(report["cases"][0]["status"], "ONE_REVIEW_CLAIM_NEEDS_SECOND_INDEPENDENT_REVIEW")
        self.assertEqual(report["accepted_training_labels"], 0)

    def test_two_agree_still_not_expert_validated(self):
        first = make_issue(self.case, reviewer="alpha")
        second = make_issue(self.case, number=11, reviewer="beta")
        report = assemble(self.queue, [first, second])
        self.assertEqual(report["cases"][0]["status"], "MATCHING_CLAIMS_NOT_INDEPENDENTLY_VERIFIED")
        self.assertEqual(report["cases"][0]["distinct_github_claim_authors"], 2)
        self.assertEqual(report["accepted_independent_expert_reviews"], 0)
        self.assertEqual(report["exportable_preference_pairs"], [])

    def test_disagreement_is_explicit_not_averaged(self):
        first = make_issue(self.case, reviewer="alpha")
        second = make_issue(self.case, number=11, reviewer="beta", verdict="unsupported")
        report = assemble(self.queue, [first, second])
        self.assertEqual(report["cases"][0]["status"], "CONFLICTING_REVIEW_CLAIMS_NEED_ADJUDICATION")
        self.assertEqual(report["accepted_training_labels"], 0)

    def test_uncertain_requires_more_evidence(self):
        first = make_issue(self.case, reviewer="alpha")
        second = make_issue(self.case, number=11, reviewer="beta",
                            verdict="uncertain - needs more evidence")
        report = assemble(self.queue, [first, second])
        self.assertEqual(report["cases"][0]["status"], "UNCERTAINTY_REQUIRES_EXPERT_EVIDENCE")

    def test_same_author_cannot_simulate_two_experts(self):
        first = make_issue(self.case, reviewer="Alpha")
        second = make_issue(self.case, number=11, reviewer="alpha")
        second["updated_at"] = "2026-10-30T10:02:00Z"
        report = assemble(self.queue, [first, second])
        self.assertEqual(report["valid_format_claims"], 2)
        self.assertEqual(report["cases"][0]["distinct_github_claim_authors"], 1)
        self.assertEqual(report["cases"][0]["review_claims"][0]["issue_number"], 11)

    def test_repository_owner_self_review_rejected(self):
        issue = make_issue(self.case, reviewer="Iniwura")
        with self.assertRaisesRegex(IntakeError, "self-review"):
            validate_claim(issue, self.rows)
        report = assemble(self.queue, [issue])
        self.assertEqual(report["format_rejected"], 1)
        self.assertEqual(report["accepted_training_labels"], 0)

    def test_bot_reviewer_rejected(self):
        issue = make_issue(self.case, reviewer="bot")
        issue["user"]["type"] = "Bot"
        with self.assertRaisesRegex(IntakeError, "bot"):
            validate_claim(issue, self.rows)

    def test_unpinned_sources_do_not_count(self):
        issue = make_issue(self.case)
        issue["body"] = issue["body"].replace(self.case["parent"], "a" * 40)
        with self.assertRaisesRegex(IntakeError, "pinned parent"):
            validate_claim(issue, self.rows)
        issue = make_issue(self.case)
        issue["body"] = issue["body"].replace(self.case["commit"], "b" * 40)
        with self.assertRaisesRegex(IntakeError, "pinned parent"):
            validate_claim(issue, self.rows)

    def test_other_project_advisory_is_not_primary_evidence(self):
        issue = make_issue(self.case)
        issue["body"] = issue["body"].replace(self.case["public_source"],
                                               "https://github.com/other/repo/security/advisories/GHSA-0000-0000-0000")
        with self.assertRaisesRegex(IntakeError, "official"):
            validate_claim(issue, self.rows)

    def test_no_checkboxes_does_not_count(self):
        issue = make_issue(self.case)
        issue["body"] = issue["body"].replace("- [x]", "- [ ]")
        with self.assertRaisesRegex(IntakeError, "attestations"):
            validate_claim(issue, self.rows)

    def test_duplicate_or_unknown_headings_rejected(self):
        issue = make_issue(self.case)
        issue["body"] += "\n\n### Public source case\n\nreplacement"
        with self.assertRaisesRegex(IntakeError, "headings"):
            validate_claim(issue, self.rows)

    def test_pretend_pr_does_not_count(self):
        issue = make_issue(self.case)
        issue["pull_request"] = {"url": "https://api.github.com/repos/x/y/pulls/10"}
        report = assemble(self.queue, [issue])
        self.assertEqual(report["structured_review_issues"], 0)

    def test_invalid_issue_number_throws_no_partial_inventory(self):
        a = make_issue(self.case)
        b = make_issue(self.case)
        with self.assertRaisesRegex(IntakeError, "duplicate"):
            assemble(self.queue, [a, b])

    def test_invalid_nonreview_is_ignored(self):
        issue = {"number": 1, "title": "Unrelated bug report", "body": ""}
        report = assemble(self.queue, [issue])
        self.assertEqual(report["issues_examined"], 1)
        self.assertEqual(report["structured_review_issues"], 0)

    def test_cli_offline_fixture_cannot_claim_public_api(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            infile = root / "issues.json"
            infile.write_text(json.dumps([make_issue(self.case)]))
            outfile = root / "status.json"
            args = ["--queue", str(ROOT / "data/real-fix-queue.json"),
                    "--issues-json", str(infile), "--out", str(outfile)]
            self.assertEqual(main(args), 0)
            report = json.loads(outfile.read_text())
            self.assertEqual(report["input_source"], "OFFLINE_UNTRUSTED_FIXTURE")
            self.assertEqual(report["accepted_training_labels"], 0)
            with self.assertRaises(SystemExit):
                main(args)


if __name__ == "__main__":
    unittest.main()
