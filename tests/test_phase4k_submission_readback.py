"""Synthetic-only adversarial tests; no network, wallet or private evaluation rows."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase4k_submission_readback import (
    COMMENT_URL, INTENT, NODE_URL, REPORTED_ROWS, ReadbackError,
    _validate_page, main, readback
)

ADDRESS = "0x" + "a" * 40  # synthetic, never a real contributor account


def sample_comment():
    return {
        "user": {"login": "Iniwura"},
        "body": f"/submit\n\n**FALSUM — {INTENT} evaluation-material contribution**\n\n"
                f"**Contributor wallet:** `{ADDRESS}`\n\n"
                f"I contributed **{REPORTED_ROWS} source-referenced evaluation preference pairs**.\n",
    }


def sample_rows(statuses):
    return [{"intent_id": INTENT, "status": s, "row_hash": f"{i+1:064x}",
             "case_id": "sensitive-internal-id", "chosen": "never-emit", "rejected": "never-emit"}
            for i, s in enumerate(statuses)]


def mock_network(statuses, comment=None):
    all_rows = sample_rows(statuses)

    def fetch(url, limit):
        if url == COMMENT_URL:
            return sample_comment() if comment is None else comment
        assert url.startswith(NODE_URL)
        from urllib.parse import parse_qs, urlsplit
        q = parse_qs(urlsplit(url).query)
        assert q["submitter"] == [ADDRESS]
        assert q["intent_id"] == [INTENT]
        offset = int(q["offset"][0])
        page_size = int(q["limit"][0])
        return {"submitter": ADDRESS, "count": len(all_rows), "rows": all_rows[offset:offset + page_size]}
    return fetch


class ReadbackTests(unittest.TestCase):
    def test_exact_20_live_eligible_statuses_aggregated_and_private(self):
        record = readback(mock_network(["eligible"] * 20))
        self.assertTrue(record["live_readback_completed"])
        self.assertEqual(record["current_eligible_rows_for_public_comment_address"], 20)
        self.assertIn("MATCHES_REPORTED", record["status"])
        blob = json.dumps(record)
        for secret in [ADDRESS, "row_hash", "case_id", "sensitive-internal-id", "never-emit",
                       "0000000000000000000000000000000000000000000000000000000000000001"]:
            self.assertNotIn(secret, blob)
        self.assertFalse(record["maintainer_approval_verified"])
        self.assertFalse(record["independent_expert_semantic_validation"])

    def test_mixed_states_cannot_claim_20_eligible(self):
        record = readback(mock_network(["eligible"] * 17 + ["admitted", "rejected", "quarantine"]))
        self.assertIn("FEWER", record["status"])
        self.assertEqual(record["current_status_counts"]["eligible"], 17)
        self.assertEqual(record["current_status_counts"]["quarantine"], 1)

    def test_public_mixed_case_address_can_use_lowercase_node_index(self):
        from urllib.parse import parse_qs, urlsplit
        mixed = "0x" + "Aa" * 20
        comment = sample_comment()
        comment["body"] = comment["body"].replace(ADDRESS, mixed)
        def fetch(url, limit):
            if url == COMMENT_URL:
                return comment
            query = parse_qs(urlsplit(url).query)
            address = query["submitter"][0]
            rows = sample_rows(["eligible"] * 20) if address == mixed.lower() else []
            return {"submitter": address, "count": len(rows), "rows": rows}
        record = readback(fetch)
        self.assertTrue(record["normalized_lowercase_retry_used"])
        self.assertEqual(record["current_eligible_rows_for_public_comment_address"], 20)
        self.assertNotIn(mixed, json.dumps(record))
        self.assertNotIn(mixed.lower(), json.dumps(record))

    def test_more_rows_does_not_claim_exact_20(self):
        self.assertIn("MORE", readback(mock_network(["eligible"] * 21))["status"])

    def test_wrong_comment_author_rejected(self):
        comment = sample_comment()
        comment["user"]["login"] = "attacker"
        with self.assertRaises(ReadbackError):
            readback(mock_network(["eligible"] * 20, comment))

    def test_changed_wallet_field_rejected(self):
        comment = sample_comment()
        comment["body"] = comment["body"].replace("**Contributor wallet:**", "**Different wallet:**")
        with self.assertRaises(ReadbackError):
            readback(mock_network(["eligible"] * 20, comment))

    def test_changed_public_row_count_rejected(self):
        comment = sample_comment()
        comment["body"] = comment["body"].replace("20 source-referenced", "21 source-referenced")
        with self.assertRaises(ReadbackError):
            readback(mock_network(["eligible"] * 20, comment))

    def test_wrong_submitter_rejected(self):
        with self.assertRaises(ReadbackError):
            _validate_page({"submitter": "0x" + "b" * 40, "count": 1,
                            "rows": sample_rows(["eligible"])}, ADDRESS, None)

    def test_unknown_status_and_wrong_intent_rejected(self):
        wrong = sample_rows(["unreviewed"])
        with self.assertRaises(ReadbackError):
            _validate_page({"submitter": ADDRESS, "count": 1, "rows": wrong}, ADDRESS, None)
        wrong = sample_rows(["eligible"])
        wrong[0]["intent_id"] = "OTHER"
        with self.assertRaises(ReadbackError):
            _validate_page({"submitter": ADDRESS, "count": 1, "rows": wrong}, ADDRESS, None)

    def test_duplicate_and_missing_row_identity_rejected(self):
        rows = sample_rows(["eligible"] * 2)
        rows[1]["row_hash"] = rows[0]["row_hash"]
        def fetch(url, limit):
            return sample_comment() if url == COMMENT_URL else {"submitter": ADDRESS, "count": 2, "rows": rows}
        with self.assertRaises(ReadbackError):
            readback(fetch)
        rows[1].pop("row_hash")
        with self.assertRaises(ReadbackError):
            readback(fetch)

    def test_multiple_pages_deduplicate_and_count(self):
        record = readback(mock_network(["eligible"] * 520 + ["admitted"] * 3))
        self.assertEqual(record["current_eligible_rows_for_public_comment_address"], 520)
        self.assertEqual(record["current_total_rows_for_public_comment_address"], 523)

    def test_count_changed_during_paging_rejected(self):
        fetch = mock_network(["eligible"] * 501)
        def mutate(url, length):
            data = fetch(url, length)
            if "offset=500" in url:
                data["count"] = 502
            return data
        with self.assertRaises(ReadbackError):
            readback(mutate)

    def test_network_error_is_unknown_not_zero_or_private_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "summary.json"
            with patch("falsum.phase4k_submission_readback.readback", side_effect=OSError("secret wallet url")):
                self.assertEqual(main(["--out", str(output)]), 0)
            report = json.loads(output.read_text())
            self.assertIsNone(report["current_eligible_rows_for_public_comment_address"])
            self.assertFalse(report["live_readback_completed"])
            self.assertNotIn("secret", output.read_text())
            with self.assertRaises(SystemExit):
                main(["--out", str(output)])


if __name__ == "__main__":
    unittest.main()
