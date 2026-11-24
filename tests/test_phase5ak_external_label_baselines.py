import unittest
from falsum import phase5ak_external_label_baselines as p


class PolicyTests(unittest.TestCase):
    def test_count_only_false_clean(self):
        r = p.predictions({"verdict": "Insecure", "vulnerability_count": 0})
        self.assertEqual(r["count_only"], "PASS")
        self.assertEqual(r["falsum_consumer"], "FLAG")
        self.assertEqual(r["strict_agreement"], "UNKNOWN")

    def test_explicit_missing_input(self):
        r = p.predictions({"verdict": "Secure", "vulnerability_count": 0,
                           "summary": "No code, configuration, or system description was provided to evaluate."})
        self.assertEqual(r["verdict_only"], "PASS")
        self.assertEqual(r["falsum_consumer"], "UNKNOWN")

    def test_unverified_count(self):
        for count in (None, True, False, -1, "0", 0.0):
            with self.subTest(count=count):
                r = p.predictions({"verdict": "Secure", "vulnerability_count": count})
                self.assertEqual(r["falsum_consumer"], "UNKNOWN")
                self.assertEqual(r["count_only"], "UNKNOWN")

    def test_conflicting_positive_verdict(self):
        r = p.predictions({"verdict": "Secure", "vulnerability_count": 1})
        self.assertEqual(r["falsum_consumer"], "UNKNOWN")

    def test_missing_response(self):
        self.assertEqual(set(p.predictions(None).values()), {"UNKNOWN"})

    def test_bounded_positive(self):
        self.assertEqual(p.predictions({"verdict": "Secure", "vulnerability_count": 0})["falsum_consumer"], "PASS")

    def test_abbreviation_collision(self):
        a = "x_0x1234" + "a"*32 + "5678.sol"
        b = "x_0x1234" + "b"*32 + "5678.sol"
        self.assertEqual(p.display_name(a), p.display_name(b))
        with self.assertRaises(p.AuditError):
            p.label_index({"items": [{"name": n, "label": "audited", "hint": False} for n in (a,b)]})


if __name__ == "__main__":
    unittest.main()
