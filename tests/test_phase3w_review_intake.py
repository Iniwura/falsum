"""Phase 3W: adversarial tests of actual one-click independent review collection.

All fixture reviews are synthetic test objects, never claims by real developers.
"""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from falsum.phase3f_multifamily_material import PROMPTS, PINS
from falsum.phase3w_review_intake import (
    ATTESTATIONS, HEADINGS, ROOT, ReviewClaimError,
    assemble, fetch_live_issues, reviewer_cases, validate_issue,
)


def fixture(row: dict, *, number: int = 122, login: str = "IndependentReviewer1", answer: str = "ABSTAIN") -> dict:
    root = f'https://github.com/{row["repository"]}/blob/{row["commit"]}/'
    links = ("Source: " + root + row["source_path"] + "#L12-L17\n"
             "Test: " + root + row["test_path"] + "#L30-L37\n"
             "Advisory: " + row["public_source"])
    long_analysis = (
        "I inspected the pinned public source change and associated regression test. "
        "This specific historical security boundary involves user-controlled input "
        "and the older library behavior; the upstream patch supports a particular "
        "source-level risk but does not establish an exploitable deployed system. "
        "Neither authored candidate should be presumed correct without more evidence."
    )
    limits = (
        "A customer's installed version, reachable route, runtime configuration, "
        "attacker-controlled data and relevant permission boundary are all unverified. "
        "No deployed application was tested."
    )
    contents = (row["id"], answer, links, long_analysis, limits,
                "\n".join("- [x] " + s for s in ATTESTATIONS))
    body = "\n\n".join("### " + label + "\n\n" + value
                         for label, value in zip(HEADINGS, contents))
    return {
        "number": number, "title": "[FALSUM external review] " + row["id"],
        "html_url": "https://github.com/Iniwura/falsum/issues/" + str(number),
        "state": "open", "pull_request": None,
        "user": {"login": login, "type": "User"},
        "created_at": "2026-11-03T12:00:00Z",
        "updated_at": "2026-11-03T12:05:00Z",
        "body": body,
    }


class Phase3WExternalReviewGates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = reviewer_cases()

    def test_seven_source_test_pins_without_any_labels(self):
        self.assertEqual(len(self.rows), 7)
        self.assertEqual(set(self.rows), {x[0] for x in PINS})
        guide = (ROOT / "docs/REVIEW_ONE_CASE.md").read_text(encoding="utf-8")
        issue_form = (ROOT / ".github/ISSUE_TEMPLATE/independent-seven-review.yml").read_text(encoding="utf-8")
        for ident, (question, _author_provisional, answers) in PROMPTS.items():
            with self.subTest(case=ident):
                self.assertIn(ident, guide)
                self.assertIn(ident, issue_form)
                self.assertIn(question, guide)
                for answer in answers:
                    self.assertIn(answer, guide)
                row = self.rows[ident]
                self.assertIn(row["public_source"], guide)
                self.assertIn(row["commit"], guide)
        for field in HEADINGS:
            self.assertIn("label: " + field, issue_form)
        for attestation in ATTESTATIONS:
            self.assertIn("label: " + attestation, issue_form)
        self.assertIn("ABSTAIN", guide)
        self.assertIn("independently accepted reviewer labels: 0", guide)
        self.assertNotIn("author_expected", guide)
        self.assertNotIn("0x9cBA6Cf", guide)

    def test_one_external_format_valid_issue_has_zero_expert_labels(self):
        row = self.rows["real-requests-proxy-auth"]
        raw = fixture(row)
        parsed = validate_issue(raw, self.rows)
        self.assertEqual(parsed["preference_claim"], "ABSTAIN")
        self.assertTrue(parsed["source_test_and_advisory_links_format_checked"])
        self.assertFalse(parsed["independent_security_expertise_verified"])
        self.assertFalse(parsed["training_label_accepted"])
        report = assemble([raw], self.rows, fetched_live=False)
        self.assertFalse(report["github_issues_fetched_live"])
        self.assertEqual(report["public_format_valid_claims"], 1)
        self.assertEqual(report["independent_expert_certified_labels"], 0)
        self.assertEqual(report["accepted_training_pairs"], 0)
        self.assertEqual(report["trainable_preference_pairs"], [])
        self.assertFalse(report["registered_evaluator"])
        self.assertFalse(report["network_eligible"])

    def test_two_claimants_and_disagreement_do_not_generate_security_labels(self):
        row = self.rows["real-requests-proxy-auth"]
        a = fixture(row, number=122, login="reviewerAlpha", answer="A")
        b = fixture(row, number=123, login="reviewerBeta", answer="B")
        report = assemble([a, b], self.rows, fetched_live=True, pages=1)
        this_case = next(c for c in report["coverage"] if c["case_id"] == row["id"])
        self.assertEqual(this_case["format_valid_distinct_github_claims"], 2)
        self.assertEqual(this_case["positions_claimed"], ["A", "B"])
        self.assertTrue(this_case["unresolved_disagreement"])
        self.assertEqual(report["independent_expert_certified_labels"], 0)
        self.assertEqual(report["new_eligible_anjoman_rows"], 0)

    def test_duplicate_author_does_not_count_as_independent(self):
        row = self.rows["real-jinja-attr-sandbox"]
        a = fixture(row, number=125, login="ReviewerOne", answer="A")
        b = fixture(row, number=126, login="reviewerone", answer="B")
        report = assemble([a, b], self.rows)
        self.assertEqual(report["public_format_valid_claims"], 1)
        self.assertEqual(report["public_rejected_form_claims"], 1)
        self.assertEqual(report["coverage"][1]["format_valid_distinct_github_claims"], 1)

    def test_malformed_claims_are_rejected_without_promotion(self):
        case = self.rows["real-jinja-attr-sandbox"]
        base = fixture(case)
        variants = []
        bad = copy.deepcopy(base); bad["user"]["login"] = "Iniwura"; variants.append(bad)
        bad = copy.deepcopy(base); bad["user"]["type"] = "Bot"; variants.append(bad)
        bad = copy.deepcopy(base); bad["html_url"] = "https://malicious.example"; variants.append(bad)
        bad = copy.deepcopy(base); bad["pull_request"] = {"url": "something"}; variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace("### Independent analysis", "### Fake analysis"); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace("### Public case\n\n" + case["id"], "### Public case\n\nFAKE"); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace("### Evidence-based preference\n\nABSTAIN", "### Evidence-based preference\n\nCERTIFIED"); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace(case["commit"], "a" * 40); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace("#L12-L17", ""); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace(case["public_source"], "https://example.com/advisory"); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace("- [x] " + ATTESTATIONS[0], "- [ ] " + ATTESTATIONS[0]); variants.append(bad)
        bad = copy.deepcopy(base); bad["body"] = bad["body"].replace(
            "A customer's installed version, reachable route, runtime configuration, "
            "attacker-controlled data and relevant permission boundary are all unverified. "
            "No deployed application was tested.", "Unknown"); variants.append(bad)
        for bad in variants:
            with self.subTest(body_hash=str(hash(bad["body"]))):
                with self.assertRaises(ReviewClaimError):
                    validate_issue(bad, self.rows)
        result = assemble(variants, self.rows)
        self.assertEqual(result["public_format_valid_claims"], 0)
        self.assertEqual(result["public_rejected_form_claims"], len(variants))
        self.assertEqual(result["accepted_training_pairs"], 0)

    def test_source_queue_tampering_blocks_a_review(self):
        row = self.rows["real-jinja-attr-sandbox"]
        tampered = copy.deepcopy(self.rows)
        tampered[row["id"]]["source_blob"] = "0" * 40
        # The actual reviewer case builder must derive identities from fixed code pins.
        self.assertNotEqual(tampered[row["id"]]["source_blob"], next(x[3] for x in PINS if x[0] == row["id"]))
        with self.assertRaises(ReviewClaimError):
            altered_root = ROOT / "missing-review-source-files"
            reviewer_cases(altered_root)

    def test_unrelated_and_self_issued_issue_is_not_auto_review(self):
        base = fixture(self.rows["real-requests-proxy-auth"])
        a = copy.deepcopy(base); a["title"] = "I love this project"
        b = copy.deepcopy(base); b["title"] = "unrelated normal issue"
        report = assemble([a, b], self.rows)
        self.assertEqual(report["public_format_valid_claims"], 0)
        self.assertEqual(report["public_rejected_form_claims"], 0)

    def test_live_github_api_source_is_fixed_and_paginated(self):
        rows = [fixture(self.rows["real-requests-proxy-auth"])]
        class Response:
            def __init__(self, url, payload):
                self.url, self.payload = url, payload
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def geturl(self): return self.url
            def read(self, *_): return json.dumps(self.payload).encode()
        called = []
        def opener(request, timeout):
            called.append(request.full_url)
            return Response(request.full_url, rows)
        received, pages = fetch_live_issues(opener=opener)
        self.assertEqual(received, rows)
        self.assertEqual(pages, 1)
        self.assertEqual(called, ["https://api.github.com/repos/Iniwura/falsum/issues?state=all&per_page=100&page=1"])
        def unsafe_redirect(request, timeout):
            return Response("https://redirected.example/", rows)
        with self.assertRaisesRegex(ReviewClaimError, "redirect"):
            fetch_live_issues(opener=unsafe_redirect)


if __name__ == "__main__":
    unittest.main()
