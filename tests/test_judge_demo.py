"""Contracts for the unified judge-facing demo summary."""
from __future__ import annotations

from copy import deepcopy
import unittest

from falsum import judge_demo as m


class JudgeDemoTests(unittest.TestCase):
    def test_demo_is_concise_evidence_backed_and_bounded(self):
        report = m.build()
        self.assertEqual(report["status"], m.STATUS)
        self.assertEqual(len(report["sixty_second_route"]), 3)
        self.assertIn("source, target and action", report["headline"])
        self.assertEqual(report["prepared_material"]["candidate_pairs"], 14)
        self.assertFalse(any("score" in step["result"].casefold() for step in report["sixty_second_route"]))
        self.assertIn("ACP", " ".join(report["limits"]))

    def test_changed_evidence_status_fails_closed(self):
        original = m._read
        try:
            def forged(root, relative):
                value = original(root, relative)
                if relative.endswith("phase5bp-public-answer-quality-result-v2.json"):
                    value = deepcopy(value)
                    value["status"] = "FABRICATED"
                return value
            m._read = forged
            with self.assertRaises(m.JudgeDemoError):
                m.build()
        finally:
            m._read = original


if __name__ == "__main__":
    unittest.main()
