"""Evidence-only reviewer challenge recipes remain runnable across platforms."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

from falsum.phase5m_real_source_sensitive_model import ROOT


class ReviewerChallengeRecipes(unittest.TestCase):
    def challenge(self, label: str) -> str:
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONDONTWRITEBYTECODE="1")
        run = subprocess.run(
            [sys.executable, "examples/reviewer_challenges.py", "--challenge", label],
            cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8",
            timeout=20, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn("Traceback", run.stdout + run.stderr)
        return run.stdout

    def test_direct_route_counterexample_is_observable(self):
        self.assertIn("PASS: CONSTRUCTED routed request becomes direct",
                      self.challenge("direct-vs-routed"))

    def test_single_byte_lock_mutation_fails_closed_without_touching_repo(self):
        path = ROOT / "data/phase5ab-original-receipt-comparability-lock.json"
        original = path.read_bytes()
        self.assertIn("PASS: CONSTRUCTED one-byte source-lock change",
                      self.challenge("tampered-lock"))
        self.assertEqual(original, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
