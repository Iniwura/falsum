"""Adversarial synthetic reviewer intake tests; NOT real independent reviewers."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5a_executed_review_census as c
from falsum.source_review_witness_gate import validated_index
from falsum.phase4p_open_source_review import load_lock

ROOT = Path(__file__).resolve().parents[1]
LOCK_FILE = ROOT / "data/phase4p-three-project-open-review-lock.json"
INDEX_FILE = ROOT / "evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
LOCK = LOCK_FILE.read_bytes()
INDEX = INDEX_FILE.read_bytes()
WITNESSES = validated_index(INDEX, LOCK)
STAGES = c.case_stages(WITNESSES, load_lock(LOCK))


def fake_issue(case_id="koa-redirect", *, number=140, author="reviewerAlpha",
               verdict="SOURCE_CHANGE_SUPPORTED_WITH_LIMITS"):
    w, stage = WITNESSES[case_id], STAGES[case_id]
    repo = w["repository"]
    parent = f"https://github.com/{repo}/blob/{w['original_git_commit']}/{stage['source_path']}#L1-L10"
    fixed = f"https://github.com/{repo}/blob/{w['fixed_git_commit']}/{stage['source_path']}#L2-L12"
    test = f"https://github.com/{repo}/blob/{w['fixed_git_commit']}/{stage['test_path']}#L3-L20"
    body_parts = (
        case_id,
        verdict,
        f"Original source {parent}\nPatched source {fixed}\n"
        "Both line spans identify the precise upstream revision and relevant changed operation.",
        f"Original upstream regression {test}\n"
        "The upstream regression compares the old behavior with the corrected source behavior "
        "but does not establish anything about a particular production deployment.",
        "My source analysis traces the changed branch through its old behavior and the new "
        "test assertion. The precise behavior is conditional on the source path used. "
        "I found this by inspecting the exact historical Git patch rather than a model verdict.",
        "A production user would need the affected historical dependency version, the exact "
        "vulnerable application route and an attacker-influenced input. "
        "The regression's synthetic setup cannot establish real exploitability.",
        "The existing regression leaves open alternate configurations and untested "
        "deployment routing. I would abstain on blanket security guarantees.",
        "Experience: source code review in public repositories. Possible conflicts: "
        "none declared. Tools used: GitHub diff and a local editor; AI support disclosed as possible.",
        "\n".join("- [x] " + statement for statement in c.DECLARATIONS),
    )
    body = "\n\n".join("### " + title + "\n\n" + value
                       for title, value in zip(c.HEADINGS, body_parts))
    return {
        "number": number,
        "title": c.PREFIX + " review of " + case_id,
        "user": {"login": author, "type": "User"},
        "html_url": f"https://github.com/Iniwura/falsum/issues/{number}",
        "state": "open", "created_at": "2026-11-19T12:00:00Z",
        "updated_at": "2026-11-19T12:03:00Z", "body": body,
    }


def replace_one_link(issue, *, source_kind="parent", new_url=None):
    name = c.fields(issue["body"])[c.HEADINGS[0]]
    w, stage = WITNESSES[name], STAGES[name]
    commit = (w["original_git_commit"] if source_kind == "parent" else w["fixed_git_commit"])
    path = stage["test_path"] if source_kind == "test" else stage["source_path"]
    old = f"https://github.com/{w['repository']}/blob/{commit}/{path}"
    issue["body"] = issue["body"].replace(old, new_url or old.replace(commit, "0" * 40))


class FourExecutedSourceReviewCensusTests(unittest.TestCase):
    def test_live_zero_review_snapshot_is_not_two_new_gold_labels(self):
        result = c.assemble(INDEX, LOCK, [], live=True)
        self.assertEqual(result["source_executed_upstream_stages"], 4)
        self.assertEqual(result["source_executed_distinct_projects"], 3)
        self.assertEqual(result["format_valid_review_claims"], 0)
        self.assertEqual(result["verified_independent_human_expert_labels"], 0)
        self.assertIsNone(result["source_semantic_review_accuracy"])
        self.assertIsNone(result["new_blind_holdout_accuracy"])
        self.assertEqual(result["training_eligible_rows"], [])
        self.assertEqual(result["input_source"], "PUBLIC_GITHUB_API")
        self.assertTrue(all("NO_FORMAT_VALID" in row["status"] for row in result["cases"]))

    def test_one_source_cited_account_is_only_an_unverified_public_claim(self):
        issue = fake_issue()
        report = c.assemble(INDEX, LOCK, [issue], live=False)
        self.assertEqual(report["format_valid_review_claims"], 1)
        row = report["cases"][0]
        self.assertEqual(row["format_valid_distinct_github_accounts"], 1)
        self.assertEqual(row["status"], "ONE_UNADJUDICATED_EXTERNAL_ACCOUNT_CLAIM")
        claim = row["reviews_needing_independent_adjudication"][0]
        self.assertEqual(claim["body_sha256"], c.digest(issue["body"]))
        self.assertFalse(claim["appsec_expertise_independently_verified"])
        self.assertFalse(claim["reviewer_is_independent_human_verified"])
        self.assertFalse(claim["eligible_for_training"])
        self.assertNotIn(issue["body"], json.dumps(report))
        self.assertNotIn("My source analysis", json.dumps(report))

    def test_four_distinct_historical_source_stages_match_actual_immutable_links(self):
        issues = [fake_issue(ident, number=i + 120, author="different"+str(i))
                  for i, ident in enumerate(WITNESSES)]
        report = c.assemble(INDEX, LOCK, issues, live=False)
        self.assertEqual(report["format_valid_review_claims"], 4)
        self.assertEqual(set(x["case_id"] for x in report["cases"]), set(WITNESSES))
        self.assertEqual(report["distinct_accounts_in_per_case_claims"], 4)
        self.assertEqual(report["verified_independent_human_expert_labels"], 0)

    def test_neither_two_matching_accounts_nor_disagreement_becomes_gold(self):
        first = fake_issue(author="alpha")
        second = fake_issue(number=141, author="beta")
        both = c.assemble(INDEX, LOCK, [first, second], live=False)
        self.assertEqual(both["cases"][0]["status"], "UNADJUDICATED_AGREEMENT_IS_NOT_GOLD")
        self.assertEqual(both["cases"][0]["format_valid_distinct_github_accounts"], 2)
        second["body"] = second["body"].replace(
            "SOURCE_CHANGE_SUPPORTED_WITH_LIMITS", "SOURCE_CHANGE_INCOMPLETE_OR_CONTRADICTED"
        )
        discord = c.assemble(INDEX, LOCK, [first, second], live=False)
        self.assertEqual(discord["cases"][0]["status"], "UNADJUDICATED_ABSTENTION_OR_DISAGREEMENT")
        self.assertEqual(discord["verified_independent_human_expert_labels"], 0)

    def test_abstain_is_accepted_but_not_source_correctness(self):
        issue = fake_issue(verdict="ABSTAIN_NEEDS_MORE_PRIMARY_EVIDENCE")
        report = c.assemble(INDEX, LOCK, [issue], live=False)
        self.assertEqual(report["cases"][0]["status"], "UNADJUDICATED_ABSTENTION_OR_DISAGREEMENT")
        self.assertIsNone(report["source_semantic_review_accuracy"])

    def test_same_author_different_issues_not_counted_as_two_reviewers(self):
        issues = [fake_issue(author="ALPHA"), fake_issue(number=141, author="alpha")]
        issues[1]["updated_at"] = "2026-11-19T12:05:00Z"
        report = c.assemble(INDEX, LOCK, issues, live=False)
        self.assertEqual(report["format_valid_review_claims"], 2)
        self.assertEqual(report["cases"][0]["format_valid_distinct_github_accounts"], 1)
        self.assertEqual(report["cases"][0]["reviews_needing_independent_adjudication"][0]["issue_number"], 141)

    def test_rejects_owner_account_bot_mismatched_canonical_url_and_pr(self):
        changes = [
            lambda x: x["user"].update(login="Iniwura"),
            lambda x: x["user"].update(type="Bot"),
            lambda x: x.update(html_url="https://evil.example/other"),
            lambda x: x.update(pull_request={"url":"https://api.github.com/pulls/1"}),
            lambda x: x.update(created_at="garbage"),
            lambda x: x.update(updated_at="2026-11-18T12:00:00Z"),
            lambda x: x.update(state="invalid"),
        ]
        for change in changes:
            with self.subTest(change=str(change)):
                issue = fake_issue()
                change(issue)
                report = c.assemble(INDEX, LOCK, [issue], live=False)
                if issue.get("pull_request"):
                    self.assertEqual(report["review_form_issues"], 0)
                else:
                    self.assertEqual(report["format_valid_review_claims"], 0)
                    self.assertEqual(report["format_rejected_review_claims"], 1)

    def test_wrong_source_fix_or_test_commit_and_unbounded_line_range_rejected(self):
        for kind in ("parent", "fixed", "test"):
            with self.subTest(kind=kind):
                issue = fake_issue()
                replace_one_link(issue, source_kind=kind)
                report = c.assemble(INDEX, LOCK, [issue], live=False)
                self.assertEqual(report["format_rejected_review_claims"], 1)
        issue = fake_issue()
        issue["body"] = issue["body"].replace("#L1-L10", "#L1-L10000")
        self.assertEqual(c.assemble(INDEX, LOCK, [issue], live=False)["format_valid_review_claims"], 0)
        issue = fake_issue()
        issue["body"] = issue["body"].replace("#L3-L20", "#L3-L20%2Fsomewhere")
        self.assertEqual(c.assemble(INDEX, LOCK, [issue], live=False)["format_valid_review_claims"], 0)

    def test_missing_declaration_duplicate_heading_and_too_short_analysis_rejected(self):
        variants = (
            lambda x: x.update(body=x["body"].replace("- [x]", "- [ ]", 1)),
            lambda x: x.update(body=x["body"] + "\n\n### Independent source assessment\n\nABSTAIN"),
            lambda x: x.update(body=x["body"].replace(
                "My source analysis traces the changed branch through its old behavior and the new "
                "test assertion. The precise behavior is conditional on the source path used. "
                "I found this by inspecting the exact historical Git patch rather than a model verdict.", "N/A")),
            lambda x: x.update(body=x["body"].replace(
                "The existing regression leaves open alternate configurations and untested "
                "deployment routing. I would abstain on blanket security guarantees.", "N/A")),
        )
        for mutate in variants:
            with self.subTest(mutate=str(mutate)):
                i = fake_issue()
                mutate(i)
                self.assertEqual(c.assemble(INDEX, LOCK, [i], live=False)["format_valid_review_claims"], 0)

    def test_wrong_source_lock_and_original_execution_hash_refused_before_review(self):
        with self.assertRaises(ValueError):
            c.assemble(INDEX, b'{"tampered":true}', [], live=False)
        index = json.loads(INDEX)
        index["receipts"][0]["raw_source_runtime_receipt_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            c.assemble(json.dumps(index).encode(), LOCK, [], live=False)

    def test_duplicate_issue_number_rejected_as_untrustworthy_public_census(self):
        one = fake_issue()
        two = fake_issue(author="other")
        with self.assertRaises(c.CensusError):
            c.assemble(INDEX, LOCK, [one, two], live=True)

    def test_offline_fixture_cannot_claim_public_github_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            issues = directory / "issues.json"
            out = directory / "review-status.json"
            issues.write_text(json.dumps([fake_issue()]))
            args = [
                "--index", str(INDEX_FILE),
                "--source-lock", str(LOCK_FILE),
                "--issues-json", str(issues), "--out", str(out),
            ]
            self.assertEqual(c.main(args), 0)
            report = json.loads(out.read_text())
            self.assertEqual(report["input_source"], "OFFLINE_UNTRUSTED_FIXTURE")
            self.assertEqual(report["verified_independent_human_expert_labels"], 0)
            with self.assertRaises(SystemExit):
                c.main(args)

    def test_irrelevant_issue_and_original_old_style_form_do_not_affect_new_review_census(self):
        unrelated = {"number": 100, "title": "[AppSec review] old research",
                     "body": "not an executed-stage source review"}
        result = c.assemble(INDEX, LOCK, [unrelated], live=True)
        self.assertEqual(result["review_form_issues"], 0)
        self.assertEqual(result["format_valid_review_claims"], 0)

if __name__ == "__main__":
    unittest.main()
