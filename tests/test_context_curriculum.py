"""Offline isolation tests for the unreviewed PR TRAIN-only research ablation."""
import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from falsum.context_curriculum import CurriculumError, build, main


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "data/draft-pr-benchmark.json"
CASEBOOK = ROOT / "data/draft-scenarios.json"


class ContextCurriculumTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.rows = [{"prompt": f"advisory evidence for fictional package-{i}",
                      "chosen": f"correct synthetic version rationale for package-{i}",
                      "rejected": f"incorrect synthetic version rationale for package-{i}"}
                     for i in range(52)]
        self.train = self.root/"train.jsonl"
        self.manifest = self.root/"pilot.json"
        self._write()

    def tearDown(self):
        self.temp.cleanup()

    def _write(self):
        self.train.write_text("".join(json.dumps(r) + "\n" for r in self.rows))
        sha = hashlib.sha256(self.train.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps({
            "intent": "SECURITY_REVIEW_GENERAL", "research_only": True,
            "network_eligible": False, "human_reviews": 0,
            "training_authorized_for_submission": False,
            "partitions": {"train": {"cases": 52, "sha256": sha},
                           "validation": {"cases": 6, "sha256": "a"*64},
                           "holdout": {"cases": 6, "sha256": "b"*64}}}))

    def test_training_only_contrasts_added_without_leakage(self):
        rows, manifest = build(self.train, self.manifest, BENCH, CASEBOOK)
        self.assertEqual(len(rows), 58)
        self.assertEqual(manifest["added_unreviewed_pr_train_pairs"], 6)
        self.assertEqual(manifest["withheld_pr_validation_cases"], 4)
        self.assertEqual(manifest["withheld_pr_holdout_cases"], 2)
        self.assertEqual(set(manifest["used_pr_family_ids"]) & set(manifest["withheld_pr_family_ids"]), set())
        self.assertFalse(manifest["training_authorized_for_submission"])
        self.assertFalse(manifest["network_eligible"])
        self.assertEqual(manifest["human_reviews"], 0)
        withheld_prompts = {r["prompt"] for r in json.loads(BENCH.read_text())["cases"]
                            if r["split"] != "train"}
        self.assertFalse(withheld_prompts & {r["prompt"] for r in rows})

    def test_source_train_edit_detected(self):
        self.train.write_text(self.train.read_text().replace("package-0", "tampered", 1))
        with self.assertRaisesRegex(CurriculumError, "differs"):
            build(self.train, self.manifest, BENCH, CASEBOOK)

    def test_duplicate_negative_rejected(self):
        self.rows[2]["rejected"] = self.rows[1]["rejected"]
        self._write()
        with self.assertRaisesRegex(CurriculumError, "duplicate negative"):
            build(self.train, self.manifest, BENCH, CASEBOOK)

    def test_status_promotion_refused(self):
        x = json.loads(self.manifest.read_text())
        x["network_eligible"] = True
        self.manifest.write_text(json.dumps(x))
        with self.assertRaisesRegex(CurriculumError, "quarantined"):
            build(self.train, self.manifest, BENCH, CASEBOOK)

    def test_benchmark_split_edit_refused(self):
        x = json.loads(BENCH.read_text())
        x["cases"][-1]["split"] = "train"
        modified = self.root / "tampered_benchmark.json"
        modified.write_text(json.dumps(x))
        with self.assertRaisesRegex(CurriculumError, "cannot verify"):
            build(self.train, self.manifest, modified, CASEBOOK)

    def test_cli_output_is_hashed_and_not_overwritten(self):
        out = self.root/"mixed.jsonl"
        metadata = self.root/"mixed-manifest.json"
        command = ["--advisory-train", str(self.train), "--pilot-manifest", str(self.manifest),
                   "--pr-benchmark", str(BENCH), "--casebook", str(CASEBOOK),
                   "--out", str(out), "--manifest", str(metadata)]
        self.assertEqual(main(command), 0)
        meta = json.loads(metadata.read_text())
        self.assertEqual(meta["partitions"]["train"]["sha256"], hashlib.sha256(out.read_bytes()).hexdigest())
        self.assertEqual(len(out.read_text().splitlines()), 58)
        with self.assertRaises(SystemExit):
            main(command)


if __name__ == "__main__":
    unittest.main()
