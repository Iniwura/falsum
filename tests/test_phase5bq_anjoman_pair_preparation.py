"""Adversarial contracts for source-backed Anjoman pair preparation."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase5bq_anjoman_pair_preparation as m


class AnjomanPairPreparationTests(unittest.TestCase):
    def setUp(self):
        self.node_path = str(Path(__file__).resolve().parents[1] / ".phase5bo-node" / "node_modules")

    def test_packet_is_source_backed_deduplicated_and_not_submitted(self):
        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            report = m.prepare()
        self.assertEqual(report["candidate_pair_count"], 14)
        self.assertEqual(report["intent"], "SECURITY_REVIEW_GENERAL")
        self.assertEqual(report["family"], "SECURITY_REVIEW")
        self.assertTrue(report["quality_gate_passed"])
        self.assertTrue(report["deduplication_passed"])
        self.assertEqual(report["upload_schema"]["intent_id"], "SECURITY_REVIEW_GENERAL")
        self.assertEqual(report["upload_schema"]["label_kind"], "preference_pair")
        self.assertEqual(len(report["upload_rows"]), 14)
        self.assertTrue(report["quality_audit"]["max_pairwise_prompt_similarity"] < 0.85)
        self.assertLessEqual(report["quality_audit"]["length_only_best_threshold_accuracy"], 0.75)
        self.assertTrue(report["quality_audit"]["answer_template_diversity_check_passed"])
        self.assertEqual(report["submission_state"], "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED")
        self.assertFalse(report["human_adjudication"])
        self.assertFalse(report["network_eligibility"])

        for row in report["upload_rows"]:
            self.assertEqual(set(row), {"prompt", "chosen", "rejected", "label_kind", "intent_id", "provenance"})
            self.assertEqual(row["label_kind"], "preference_pair")
            self.assertEqual(row["intent_id"], "SECURITY_REVIEW_GENERAL")
            self.assertEqual(row["provenance"]["source_kind"], "generated")

    def test_each_pair_has_immutable_provenance_and_real_competing_claims(self):
        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            rows = m.prepare()["rows"]
        for row in rows:
            self.assertRegex(row["provenance"]["advisory_source_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(row["provenance"]["registry_source_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotEqual(row["better_answer"]["decision"], row["worse_answer"]["decision"])
            self.assertEqual(row["better_answer"]["scope"], "version_applicability_only")
            self.assertEqual(row["worse_answer"]["scope"], "version_applicability_only")
            self.assertNotIn("answer_token", json.dumps(row))
            self.assertEqual(row["submission_state"], "CANDIDATE_NOT_SUBMITTED")

    def test_validation_rejects_duplicate_question_and_inflated_acceptance(self):
        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            forged = m.prepare()
        forged["rows"].append(dict(forged["rows"][0]))
        with self.assertRaises(m.PairPreparationError):
            m.validate(forged)

        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            forged = m.prepare()
        forged["rows"][0]["network_eligible"] = True
        with self.assertRaises(m.PairPreparationError):
            m.validate(forged)

        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            forged = m.prepare()
        forged["upload_rows"][1] = dict(forged["upload_rows"][0])
        with self.assertRaises(m.PairPreparationError):
            m.validate(forged)

        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            forged = m.prepare()
        forged["upload_rows"][0]["intent_id"] = "SECURITY_REVIEW"
        with self.assertRaises(m.PairPreparationError):
            m.validate(forged)

        with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
            forged = m.prepare()
        repeated = forged["upload_rows"][0]["chosen"]
        for row in forged["upload_rows"]:
            row["chosen"] = repeated
        with self.assertRaises(m.PairPreparationError):
            m.validate(forged)

    def test_write_once_and_cli_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "pairs.json"
            jsonl = Path(temp) / "SECURITY_REVIEW_GENERAL.jsonl"
            with patch.dict("os.environ", {"FALSUM_PHASE5BO_NODE_PATH": self.node_path}):
                self.assertEqual(m.main(["--out", str(out), "--jsonl-out", str(jsonl)]), 0)
            self.assertTrue(out.is_file())
            self.assertTrue(jsonl.is_file())
            lines = jsonl.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 14)
            self.assertTrue(all(set(json.loads(line)) == {"prompt", "chosen", "rejected", "label_kind", "intent_id", "provenance"}
                                for line in lines))
            with self.assertRaises(SystemExit):
                m.main(["--out", str(out)])


if __name__ == "__main__":
    unittest.main()
