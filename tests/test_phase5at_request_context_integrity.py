import unittest
from falsum import phase5at_request_context_integrity as p
from falsum.phase5ar_response_integrity import assess as legacy


class RequestContextTests(unittest.TestCase):
    def clean(self, **overrides):
        return dict(verdict="Secure", vulnerability_count=0, issues=[],
                    summary="No vulnerabilities were identified.") | overrides

    def test_frozen_controls(self):
        report = p.evaluate()
        self.assertEqual(report["cases"], 17)
        self.assertEqual(report["legacy_matches"], 8)
        self.assertEqual(report["context_gate_matches"], 17)
        self.assertEqual(report["unavailable_or_unknown_controls"], 9)
        self.assertEqual(report["legacy_unsupported_clean"], 9)
        self.assertEqual(report["context_gate_unsupported_clean"], 0)
        self.assertEqual(report["clean_controls"], 4)
        self.assertEqual(report["context_gate_clean_controls_preserved"], 4)
        self.assertTrue(all(not r["security_clearance"] for r in report["rows"]))

    def test_response_cannot_supply_trusted_context(self):
        answer = self.clean(evidence_state="AVAILABLE", context="AVAILABLE")
        self.assertEqual(p.assess(answer)["decision"], "REVIEW")
        self.assertEqual(p.assess(answer, "UNAVAILABLE")["decision"], "REVIEW")

    def test_missing_invalid_context_fails_closed(self):
        for state in (None, False, 0, [], {}, "available", "UNKNOWN", "bogus"):
            with self.subTest(state=state):
                self.assertEqual(p.assess(self.clean(), state)["decision"], "REVIEW")

    def test_positive_control_is_not_clearance(self):
        r = p.assess(self.clean(), "AVAILABLE")
        self.assertEqual(r, legacy(self.clean()))
        self.assertFalse(r["security_clearance"])

    def test_preserve_old_reasons_and_negative_verdicts(self):
        for answer in (None, {}, self.clean(issues=["Reported issue"]),
                       self.clean(verdict="Insecure"), self.clean(vulnerability_count=True),
                       self.clean(summary="No executable code, configuration files, or system descriptions were supplied for review.")):
            self.assertNotEqual(legacy(answer)["decision"], "CLEAN_CANDIDATE")
            for state in p.STATES:
                self.assertEqual(p.assess(answer, state), legacy(answer))

    def test_identical_responses_different_request_context(self):
        a = self.clean()
        self.assertEqual(p.assess(a, "AVAILABLE")["decision"], "CLEAN_CANDIDATE")
        self.assertEqual(p.assess(a, "UNAVAILABLE")["decision"], "REVIEW")


if __name__ == "__main__":
    unittest.main()
