import copy
import json
import unittest
from falsum import phase5an_coverage_taxonomy as p


class CoverageTests(unittest.TestCase):
    def hold(self, length=2400):
        return {"kind": "decision", "input": {"name": "test.sol"}, "verdict": "HOLD",
                "evidence": [], "receipts": [], "wasted_receipts": [], "cost_usd": 0,
                "reasons": [f"too long to review: {length} characters without comments, "
                            "over the 2000-character limit of the review Intents; split the deliverable or review it another way"]}

    def test_exact_reason(self):
        self.assertEqual(p.preflight_length(self.hold(), []), 2400)
        self.assertEqual(p.classify(self.hold(), []), "INPUT_LIMIT_PREFLIGHT_HOLD")
        self.assertIsNone(p.preflight_length(self.hold(2000), []))

    def test_no_inference_from_absence(self):
        d = self.hold()
        d["reasons"] = ["unknown"]
        self.assertEqual(p.classify(d, []), "UNEXPLAINED_NO_ANSWER_RECORD")

    def test_contradictory_records(self):
        for key, value in (("cost_usd", 0.01), ("cost_usd", False), ("receipts", ["x"]),
                           ("wasted_receipts", ["x"]), ("verdict", "SHIP")):
            with self.subTest(key=key, value=value):
                d = self.hold()
                d[key] = value
                self.assertIsNone(p.preflight_length(d, []))
        self.assertIsNone(p.preflight_length(self.hold(), [{"kind": "error", "intent": "OTHER"}]))

    def test_failure_preserved_across_retry(self):
        err = {"kind": "error", "intent": p.INTENT}
        d = self.hold()
        first = copy.deepcopy(d)
        first["reasons"] = ["failed"]
        first["evidence"] = [{"intent": p.INTENT, "ok": False}]
        raw = "\n".join(json.dumps(x) for x in (err, first, d)).encode()
        r = p.examine(raw)
        self.assertEqual(r["latest_cases"], 1)
        self.assertEqual(r["decision_events"], 2)
        self.assertEqual(r["preflight_cases_with_earlier_failure"], 1)

    def test_orphan_and_inconsistent_failure(self):
        err = {"kind": "error", "intent": p.INTENT}
        with self.assertRaises(ValueError):
            p.classify(self.hold(), [err])
        with self.assertRaises(ValueError):
            p.histories(json.dumps(err).encode())


if __name__ == "__main__":
    unittest.main()
