import unittest
from falsum import phase5ar_response_integrity as p


class ResponseGateTests(unittest.TestCase):
    def clean(self, **overrides):
        return dict(verdict="Secure", vulnerability_count=0, issues=[],
                    summary="The supplied source was reviewed.", **{}) | overrides

    def test_consistent_clean_is_only_candidate(self):
        r=p.assess(self.clean())
        self.assertEqual(r["decision"],"CLEAN_CANDIDATE")
        self.assertFalse(r["security_clearance"])

    def test_explicit_missing_source_three_wordings(self):
        for text in ("No code, configuration, or system description was provided to evaluate.",
                     "The input is merely a token contract address query with no executable code, configuration, or data handling to assess.",
                     "No executable code, configuration files, or system descriptions were supplied for review."):
            r=p.assess(self.clean(summary=text))
            self.assertIn("EXPLICIT_NO_CODE_EVIDENCE",r["reasons"])
            self.assertEqual(r["decision"],"REVIEW")

    def test_issue_bearing_clean_needs_review(self):
        r=p.assess(self.clean(issues=["Reported issue"]))
        self.assertIn("REPORTED_ISSUES_REQUIRE_REVIEW",r["reasons"])
        self.assertEqual(r["decision"],"REVIEW")

    def test_negative_verdict_not_erased(self):
        self.assertEqual(p.assess(self.clean(verdict="Insecure"))["decision"],"FLAG")

    def test_invalid_counts_and_issues_not_clean(self):
        for v in (None,False,0.0,-1,1,"0"):
            self.assertEqual(p.assess(self.clean(vulnerability_count=v))["decision"],"REVIEW")
        for v in ("",{},[None],[" "]):
            self.assertEqual(p.assess(self.clean(issues=v))["decision"],"REVIEW")

    def test_no_evidence_pattern_not_broad_keyword(self):
        for s in ("The input is only checked against the zero address.",
                  "The contract only has a single owner address.",
                  "The supplied code checks the address before transfer."):
            self.assertEqual(p.assess(self.clean(summary=s))["decision"],"CLEAN_CANDIDATE")

    def test_incomplete_and_missing_summary(self):
        for f in (None,{},self.clean(summary=""),self.clean(summary=None)):
            self.assertEqual(p.assess(f)["decision"],"REVIEW")
        self.assertFalse(p.assess({})["security_clearance"])

    def test_source_parser_rejects_unexpected_declaration(self):
        with self.assertRaises(ValueError):
            p.declarations(b"const unexpected = bought('security', 'SECURITY_REVIEW_GENERAL', {verdict: 'Secure'}, {});")


if __name__ == "__main__":
    unittest.main()
