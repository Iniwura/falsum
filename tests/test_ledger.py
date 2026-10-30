"""Tests use invented, non-production advisories; never submit these fixtures."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from falsum.cli import main
from falsum.ledger import LedgerError, export_jsonl, export_pairs, validate_ledger


def fixture():
    return {
        "schema_version": 1,
        "evidence": [
            {"id": "e1", "ecosystem": "npm", "package": "sample-package", "version": "1.0.0",
             "advisory_id": "CVE-2025-12345", "verdict": "affected", "source_url": "https://example.org/advisory/1",
             "source_excerpt": "Test-only example about a vulnerable version, not a real advisory.",
             "source_sha256": hashlib.sha256(b"fixture-one").hexdigest(), "review_status": "reviewed",
             "reviewer": "fixture-reviewer", "reviewed_on": "2026-10-30"}
        ],
        "pairs": [
            {"id": "p1", "intent_id": "SECURITY_REVIEW_GENERAL", "split": "train", "review_status": "reviewed",
             "reviewer": "fixture-reviewer", "reviewed_on": "2026-10-30", "evidence_ids": ["e1"],
             "prompt": "Review this fictional package at version 1.0.0 for the test advisory.",
             "chosen": "The fictional advisory identifies this version as affected; request remediation.",
             "rejected": "The fictional advisory identifies this version as patched; no action is needed."}
        ]
    }


class TestLedger(unittest.TestCase):
    def test_valid_fixture(self):
        self.assertEqual(validate_ledger(fixture()), [])

    def test_export_shape(self):
        rows = export_pairs(fixture(), "train")
        self.assertEqual(set(rows[0]), {"prompt", "chosen", "rejected"})
        self.assertEqual(json.loads(export_jsonl(fixture(), "train"))["prompt"], rows[0]["prompt"])

    def test_missing_source(self):
        data = fixture(); data["evidence"][0]["source_url"] = ""
        self.assertTrue(any("HTTPS" in x for x in validate_ledger(data)))

    def test_http_rejected(self):
        data = fixture(); data["evidence"][0]["source_url"] = "http://example.org/a"
        self.assertTrue(validate_ledger(data))

    def test_bad_advisory_id(self):
        data = fixture(); data["evidence"][0]["advisory_id"] = "random"
        self.assertTrue(any("advisory_id" in x for x in validate_ledger(data)))

    def test_missing_snapshot_hash(self):
        data = fixture(); data["evidence"][0]["source_sha256"] = ""
        self.assertTrue(any("snapshot SHA-256" in x for x in validate_ledger(data)))

    def test_unreviewed_evidence_cannot_support_reviewed_pair(self):
        data = fixture(); data["evidence"][0]["review_status"] = "draft"
        self.assertTrue(any("unreviewed evidence" in x for x in validate_ledger(data)))

    def test_same_answer(self):
        data = fixture(); data["pairs"][0]["rejected"] = data["pairs"][0]["chosen"]
        self.assertTrue(any("identical" in x for x in validate_ledger(data)))

    def test_unbalanced_answers(self):
        data = fixture(); data["pairs"][0]["rejected"] = "Bad answer repeated " * 80
        self.assertTrue(any("unbalanced" in x for x in validate_ledger(data)))

    def test_unknown_evidence(self):
        data = fixture(); data["pairs"][0]["evidence_ids"] = ["unknown"]
        self.assertTrue(any("unknown evidence" in x for x in validate_ledger(data)))

    def test_duplicate_evidence_id(self):
        data = fixture(); data["evidence"].append(copy.deepcopy(data["evidence"][0]))
        self.assertTrue(any("duplicate id" in x for x in validate_ledger(data)))

    def test_duplicate_pair_id(self):
        data = fixture(); data["pairs"].append(copy.deepcopy(data["pairs"][0]))
        self.assertTrue(any("duplicate id" in x for x in validate_ledger(data)))

    def test_repeated_negative(self):
        data = fixture(); second = copy.deepcopy(data["pairs"][0]); second["id"] = "p2"
        second["prompt"] = "Analyze an entirely different fictional software component for security mistakes."
        data["pairs"].append(second)
        self.assertTrue(any("repeated rejected" in x for x in validate_ledger(data)))

    def test_similar_prompt(self):
        data = fixture(); second = copy.deepcopy(data["pairs"][0]); second["id"] = "p2"
        second["rejected"] = "This library version is definitely safe, so close the security review as clean."
        data["pairs"].append(second)
        self.assertTrue(any("prompt too similar" in x for x in validate_ledger(data)))

    def test_cross_split_leakage(self):
        data = fixture(); second = copy.deepcopy(data["pairs"][0]); second["id"] = "p2"
        second["split"] = "holdout"; second["prompt"] = "Assess the supplied dependency file for reproducible warning evidence and attack prerequisites."
        second["rejected"] = "The listed finding has already been resolved, and the software needs no changes."
        data["pairs"].append(second)
        self.assertTrue(any("dataset leakage" in x for x in validate_ledger(data)))

    def test_draft_not_exported(self):
        data = fixture(); data["pairs"][0]["review_status"] = "draft"
        with self.assertRaises(LedgerError):
            export_pairs(data, "train")

    def test_invalid_split_not_exported(self):
        with self.assertRaises(LedgerError):
            export_pairs(fixture(), "bogus")

    def test_cli_round_trip(self):
        with tempfile.TemporaryDirectory() as root:
            source, output = Path(root) / "ledger.json", Path(root) / "out.jsonl"
            source.write_text(json.dumps(fixture()), encoding="utf-8")
            self.assertEqual(main(["validate", str(source)]), 0)
            self.assertEqual(main(["export", str(source), "--split", "train", "--out", str(output)]), 0)
            self.assertEqual(len(output.read_text().splitlines()), 1)

    def test_cli_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "ledger.json"
            source.write_text("not json", encoding="utf-8")
            self.assertEqual(main(["validate", str(source)]), 1)

    def test_malformed_root(self):
        self.assertTrue(validate_ledger({"schema_version": 2, "evidence": [], "pairs": []}))


if __name__ == "__main__":
    unittest.main()
