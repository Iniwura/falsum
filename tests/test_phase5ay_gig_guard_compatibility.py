import unittest

from falsum.phase5ay_gig_guard_compatibility import postcondition, SEC, CODE


def reviews(**overrides):
    sec = dict(verdict="Secure", vulnerability_count=0, issues=[],
               summary="The provided source was reviewed.")
    sec.update(overrides)
    return [dict(intent=SEC, ok=True, result=sec),
            dict(intent=CODE, ok=True, result={"verdict": "Approve"})]


class CompatibilityTests(unittest.TestCase):
    def test_clean_preserves_ship_without_clearance(self):
        r = postcondition("SHIP", reviews())
        self.assertEqual(r["verdict"], "SHIP")
        self.assertFalse(r["security_clearance"])

    def test_existing_restrictions_never_promoted(self):
        for v in ("FIX", "HOLD"):
            for evidence in (reviews(), [], None):
                self.assertEqual(postcondition(v, evidence)["verdict"], v)

    def test_missing_and_duplicate_review_hold(self):
        for e in (reviews()[:1], reviews()[1:], [], reviews() + reviews()[:1], None, [1]):
            self.assertEqual(postcondition("SHIP", e)["verdict"], "HOLD")

    def test_invalid_and_failed_record_hold(self):
        for value in (False, 1, None):
            e = reviews()
            e[1]["ok"] = value
            self.assertEqual(postcondition("SHIP", e)["verdict"], "HOLD")
        e = reviews()
        e[1]["result"] = {}
        self.assertEqual(postcondition("SHIP", e)["verdict"], "HOLD")

    def test_context_aware_baseline_and_integrity_difference(self):
        for kw in (dict(vulnerability_count=1), dict(issues=["reported concern"]),
                   dict(summary="No code, configuration, or system description was provided to evaluate"),
                   dict(verdict="Insecure"), dict(summary="")):
            r = postcondition("SHIP", reviews(**kw))
            self.assertEqual(r["availability_baseline"], "SHIP")
            self.assertEqual(r["verdict"], "HOLD")

    def test_unknown_original_is_hold(self):
        self.assertEqual(postcondition("GO", reviews())["verdict"], "HOLD")
