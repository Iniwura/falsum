"""Offline integrity and tampering tests. Public patches are not expert labels."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.real_fix_corpus import (
    RealFixError, assemble, load_queue, main, reviewer_packet, verify_commit,
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE_QUEUE = ROOT / "data/real-fix-queue.json"


def fake_commit(row):
    return {
        "sha": row["commit"],
        "parents": [{"sha": row["parent"]}],
        "html_url": f'https://github.com/{row["repository"]}/commit/{row["commit"]}',
        "files": [
            {"filename": row["source_path"], "sha": row["source_blob"],
             "status": "modified", "patch": "@@ -1,1 +1,1 @@\n-old risky code\n+new protected code"},
            {"filename": row["test_path"], "sha": row["test_blob"],
             "status": "modified", "patch": "@@ -0,0 +1,1 @@\n+regression test added"},
        ],
    }


class RealFixTests(unittest.TestCase):
    def setUp(self):
        self.queue = load_queue(SOURCE_QUEUE)
        self.responses = {r["commit"]: fake_commit(r) for r in self.queue["cases"]}

    def fetch(self, url):
        sha = url.rsplit("/", 1)[-1]
        return copy.deepcopy(self.responses[sha])

    def test_pinned_real_queue_accepts_source_metadata(self):
        self.assertEqual(len(self.queue["cases"]), 4)
        self.assertEqual({r["repository"] for r in self.queue["cases"]},
                         {"psf/requests", "aio-libs/aiohttp", "pallets/jinja", "axios/axios"})

    def test_builds_real_patch_evidence_without_model_labels(self):
        report = assemble(self.queue, self.fetch)
        self.assertEqual(report["status"], "SOURCE_VERIFIED_LABELS_UNREVIEWED")
        self.assertEqual(report["source_verified"], 4)
        self.assertEqual(report["independent_human_reviews"], 0)
        self.assertFalse(report["training_authorized"])
        self.assertFalse(report["network_eligible"])
        self.assertTrue(report["not_usable_as_accuracy_benchmark"])
        for row in report["cases"]:
            self.assertIsNone(row["proposed_preference_label"])
            self.assertEqual(len(row["source"]["sha256"]), 64)
        questions = reviewer_packet(report)
        self.assertEqual(questions["proposed_labels"], 0)
        self.assertEqual(questions["human_reviews"], 0)
        for question in questions["questions"]:
            self.assertNotIn("chosen", question)
            self.assertNotIn("rejected", question)
            self.assertNotIn("correct", question)
            self.assertIn("source_patch", question)
            self.assertIn("regression_test_patch", question)

    def test_parent_tampering_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        obj["parents"][0]["sha"] = "f"*40
        with self.assertRaisesRegex(RealFixError, "parent mismatch"):
            verify_commit(row, obj)

    def test_wrong_source_blob_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        obj["files"][0]["sha"] = "0"*40
        with self.assertRaisesRegex(RealFixError, "path/blob"):
            verify_commit(row, obj)

    def test_wrong_canonical_url_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        obj["html_url"] = "https://example.com/other-commit"
        with self.assertRaisesRegex(RealFixError, "canonical commit"):
            verify_commit(row, obj)

    def test_missing_test_patch_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        del obj["files"][1]["patch"]
        with self.assertRaisesRegex(RealFixError, "textual patch"):
            verify_commit(row, obj)

    def test_missing_source_removal_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        obj["files"][0]["patch"] = "@@ -0,0 +1,1 @@\n+only additions"
        with self.assertRaisesRegex(RealFixError, "removed source"):
            verify_commit(row, obj)

    def test_oversized_patch_rejected(self):
        row = self.queue["cases"][0]
        obj = fake_commit(row)
        obj["files"][0]["patch"] += "\n+" + "A"*15000
        with self.assertRaisesRegex(RealFixError, "oversized"):
            verify_commit(row, obj)

    def test_advisory_host_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            q = copy.deepcopy(self.queue)
            q["cases"][0]["public_source"] = "https://attacker.example/advisory"
            p = Path(d)/"queue.json"
            p.write_text(json.dumps(q))
            with self.assertRaisesRegex(RealFixError, "advisory URL"):
                load_queue(p)

    def test_cross_project_leakage_refused(self):
        with tempfile.TemporaryDirectory() as d:
            q = copy.deepcopy(self.queue)
            q["cases"][1]["repository"] = q["cases"][0]["repository"]
            q["cases"][1]["public_source"] = (
                f'https://github.com/{q["cases"][1]["repository"]}/security/advisories/{q["cases"][1]["advisory"]}')
            p = Path(d)/"queue.json"
            p.write_text(json.dumps(q))
            with self.assertRaisesRegex(RealFixError, "duplicated"):
                load_queue(p)

    def test_case_status_promotion_refused(self):
        with tempfile.TemporaryDirectory() as d:
            q = copy.deepcopy(self.queue)
            q["status"] = "ELIGIBLE"
            p = Path(d)/"queue.json"
            p.write_text(json.dumps(q))
            with self.assertRaisesRegex(RealFixError, "status"):
                load_queue(p)

    def test_review_packet_requires_zero_human_reviews(self):
        report = assemble(self.queue, self.fetch)
        report["independent_human_reviews"] = 1
        with self.assertRaisesRegex(RealFixError, "unreviewed"):
            reviewer_packet(report)

    def test_cli_creates_distinct_outputs_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cmd = ["--queue", str(SOURCE_QUEUE), "--out", str(root/"evidence.json"),
                   "--reviewer-out", str(root/"questions.json")]
            with patch("falsum.real_fix_corpus.fetch_github_commit", side_effect=self.fetch):
                self.assertEqual(main(cmd), 0)
                self.assertEqual(len(json.loads((root/"questions.json").read_text())["questions"]), 4)
                with self.assertRaises(SystemExit):
                    main(cmd)


if __name__ == "__main__":
    unittest.main()
