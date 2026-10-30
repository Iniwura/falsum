"""Phase 2e: all casebook outputs are diagnostic and non-submittable."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.preflight import diagnostic_metrics, draft_triplets, preflight_casebook, render_for_judgment
from falsum.scenarios import read_casebook

BOOK = Path(__file__).resolve().parents[1] / "data" / "draft-scenarios.json"


class PreflightTests(unittest.TestCase):
    def test_actual_casebook_is_not_ready(self):
        report = preflight_casebook(BOOK)
        self.assertEqual(report["n"], 6)
        self.assertEqual(report["total_cases"], 12)
        self.assertEqual(report["independently_reviewed"], 0)
        self.assertFalse(report["preflight_clear"])
        self.assertFalse(report["model_training_authorized"])
        self.assertFalse(report["network_eligible"])
        self.assertTrue(any("50" in x for x in report["failures"]))

    def test_upstream_scoring_template(self):
        self.assertEqual(render_for_judgment("task", "answer"), "### Task:\ntask\n\n### Answer:\nanswer")

    def test_drafts_get_no_training_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            report = preflight_casebook(BOOK, diagnostic_dir=d)
            dir = Path(d)
            self.assertTrue((dir / "DRAFT-ONLY-NOT-FOR-TRAINING.jsonl").is_file())
            status = json.loads((dir / "STATUS-NOT-ELIGIBLE.json").read_text())
            self.assertFalse(status["network_eligible"])
            self.assertFalse(status["model_training_authorized"])
            data = [json.loads(s) for s in (dir / "DRAFT-ONLY-NOT-FOR-TRAINING.jsonl").read_text().splitlines()]
            self.assertEqual(set(data[0]), {"prompt", "chosen", "rejected"})
            self.assertEqual(report["diagnostic_sha256"], status["diagnostic_sha256"])

    def test_duplicate_negative_detected(self):
        r = draft_triplets(read_casebook(BOOK))
        second = copy.deepcopy(r[0]); r.append(second)
        self.assertTrue(any("2%" in issue or "80%" in issue for issue in diagnostic_metrics(r)["failures"]))

    def test_length_shortcut_detected(self):
        rows = [{"prompt": f"Review issue {i}", "chosen": "The security claim is precisely supported by given evidence.", "rejected": "No."} for i in range(50)]
        self.assertTrue(any("65%" in reason for reason in diagnostic_metrics(rows)["failures"]))

    def test_50_unique_pairs_can_pass_simple_mirror_not_official(self):
        rows = []
        for i in range(50):
            chosen = "A" * (130 if i % 2 else 110) + f" chosen {i}"
            rejected = "B" * (110 if i % 2 else 130) + f" rejected {i}"
            rows.append({"prompt": f"task {i}", "chosen": chosen, "rejected": rejected})
        m = diagnostic_metrics(rows)
        self.assertTrue(m["preflight_clear"])
        self.assertFalse(m["official_gate_ran"])

    def test_wrong_split_blocked(self):
        with self.assertRaises(ValueError):
            draft_triplets(read_casebook(BOOK), "bogus")

    def test_integrity_failure_blocks_diagnostic_file(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            bad = copy.deepcopy(read_casebook(BOOK))
            (tmp / "draft-scenarios.json").write_text(json.dumps(bad))
            with self.assertRaises(ValueError):
                preflight_casebook(tmp / "draft-scenarios.json", diagnostic_dir=tmp / "out")
            self.assertFalse((tmp / "out" / "DRAFT-ONLY-NOT-FOR-TRAINING.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
