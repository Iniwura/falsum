"""Ensure independent reviewer questions never ship their answer key."""
import json
import tempfile
import unittest
from pathlib import Path

from falsum.pr_review_packet import PRPacketError, generate, write_packet, main

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "data/draft-pr-benchmark.json"
CASEBOOK = ROOT / "data/draft-scenarios.json"


class PRPacketTests(unittest.TestCase):
    def test_blinded_questions_have_no_answer_labels(self):
        blind, private = generate(BENCH, CASEBOOK)
        self.assertEqual(len(blind), 12)
        self.assertEqual(len(private), 12)
        self.assertEqual({r["case_id"] for r in blind}, {r["case_id"] for r in private})
        for row in blind:
            self.assertNotIn("proposed_label", row)
            self.assertNotIn("split", row)
            self.assertNotIn("contrast_chosen", row)
            self.assertNotIn("expected_status", row)
            self.assertIn(chr(96)*3 + "diff", row["prompt_and_diff"])
            self.assertTrue(row["pinned_security_guidance"])

    def test_public_and_private_are_separate(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            public, private = root/"questions", root/"labels"
            r = write_packet(BENCH, CASEBOOK, public, private)
            self.assertEqual(r["questions"], 12)
            self.assertFalse(r["network_eligible"])
            self.assertEqual(r["human_reviews"], 0)
            self.assertFalse((public/"DO-NOT-SHARE-PR-ANSWER-KEY.jsonl").exists())
            self.assertFalse((private/"BLIND-PR-REVIEW.jsonl").exists())
            rows = (public/"BLIND-PR-REVIEW.jsonl").read_text().splitlines()
            self.assertEqual(len(rows), 12)
            self.assertTrue(all("proposed_label" not in json.loads(x) for x in rows))

    def test_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            pub, prv = root/"pub",root/"private"
            write_packet(BENCH, CASEBOOK, pub, prv)
            with self.assertRaisesRegex(PRPacketError, "overwrite"):
                write_packet(BENCH, CASEBOOK, pub, prv)

    def test_nested_outputs_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaisesRegex(PRPacketError, "disjoint"):
                write_packet(BENCH, CASEBOOK, root/"pub", root/"pub"/"private")

    def test_private_key_inside_repo_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(PRPacketError, "outside repository"):
                write_packet(BENCH, CASEBOOK, Path(d)/"public", ROOT/"private")

    def test_casebook_checksum_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            fake_casebook = Path(d)/"casebook.json"
            fake_casebook.write_text(CASEBOOK.read_text().replace("github-token", "github-token-tampered", 1))
            with self.assertRaises(ValueError):
                generate(BENCH, fake_casebook)

    def test_cli_public_packet_with_private_key_path(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            result = main(["--benchmark", str(BENCH), "--casebook", str(CASEBOOK),
                           "--public-out", str(root/"public"), "--private-out", str(root/"private")])
            self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
