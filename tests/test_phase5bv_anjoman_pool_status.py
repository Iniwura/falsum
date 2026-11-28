from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5bv_anjoman_pool_status as m


def status_payload() -> dict:
    return {
        "intent_id": "SECURITY_REVIEW_GENERAL",
        "counts": [
            {"status": "eligible", "count": 1180},
            {"status": "quarantine", "reason": "rate_limited", "count": 40},
        ],
        "by_state": {"eligible": 1180, "quarantine": 40},
        "submitters": 7,
        "eligible_submitters": 6,
        "min_submitters": 5,
        "snapshot": {
            "corpus_version": "new-snapshot",
            "rows": 1180,
            "submitters": 6,
            "activation_epoch": 1043,
        },
        "active_snapshot": {
            "corpus_version": "active-snapshot",
            "rows": 1104,
            "submitters": 6,
            "activation_epoch": 1041,
        },
        "current_epoch": 1042,
        "rows": [{"prompt": "must never be copied"}],
        "submitter_addresses": ["0xmust-not-be-copied"],
    }


class AnjomanAggregatePoolStatusTests(unittest.TestCase):
    def test_reports_active_pool_without_claiming_latest_snapshot_or_user_row_use(self):
        report = m.parse_status(
            json.dumps(status_payload()).encode(),
            observed_utc="2026-11-28T00:00:00+00:00",
        )
        pool = report["pool"]
        self.assertEqual(report["intent_id"], "SECURITY_REVIEW_GENERAL")
        self.assertEqual(pool["eligible_submitters"], 6)
        self.assertEqual(pool["min_submitters"], 5)
        self.assertTrue(pool["active_snapshot_meets_contributor_minimum"])
        self.assertTrue(pool["active_pool_available_for_current_epoch"])
        self.assertFalse(pool["latest_snapshot_is_active"])
        self.assertEqual(pool["active_snapshot"]["activation_epoch"], 1041)
        self.assertFalse(report["contribution"]["operator_rows_in_active_snapshot_verified"])
        self.assertFalse(report["contribution"]["operator_rows_used_for_ranking_verified"])

    def test_waiting_latest_snapshot_does_not_hide_current_active_snapshot(self):
        payload = status_payload()
        payload["snapshot"]["activation_epoch"] = 1044
        payload["current_epoch"] = 1043
        report = m.parse_status(json.dumps(payload).encode())
        self.assertTrue(report["pool"]["active_pool_available_for_current_epoch"])
        self.assertFalse(report["pool"]["latest_snapshot_is_active"])

    def test_active_snapshot_below_five_contributors_is_not_pool_ready(self):
        payload = status_payload()
        payload["active_snapshot"]["submitters"] = 4
        report = m.parse_status(json.dumps(payload).encode())
        self.assertFalse(report["pool"]["active_snapshot_meets_contributor_minimum"])
        self.assertFalse(report["pool"]["active_pool_available_for_current_epoch"])

    def test_missing_active_snapshot_is_not_pool_ready(self):
        payload = status_payload()
        payload["active_snapshot"] = None
        report = m.parse_status(json.dumps(payload).encode())
        self.assertIsNone(report["pool"]["active_snapshot"])
        self.assertFalse(report["pool"]["active_pool_available_for_current_epoch"])

    def test_live_node_configured_minimum_can_differ_from_documentation_default(self):
        payload = status_payload()
        payload["submitters"] = 3
        payload["eligible_submitters"] = 3
        payload["min_submitters"] = 3
        payload["active_snapshot"]["submitters"] = 3
        report = m.parse_status(json.dumps(payload).encode())
        self.assertTrue(report["pool"]["active_snapshot_meets_contributor_minimum"])
        self.assertTrue(report["pool"]["active_pool_available_for_current_epoch"])

    def test_wrong_intent_is_rejected(self):
        payload = status_payload()
        payload["intent_id"] = "CODE_REVIEW_GENERAL"
        with self.assertRaises(m.PoolStatusError):
            m.parse_status(json.dumps(payload).encode())

    def test_duplicate_json_keys_are_rejected(self):
        raw = b'{"intent_id":"SECURITY_REVIEW_GENERAL","intent_id":"CODE_REVIEW_GENERAL"}'
        with self.assertRaises(m.PoolStatusError):
            m.parse_status(raw)

    def test_malformed_counts_and_boolean_numbers_are_rejected(self):
        payload = status_payload()
        payload["counts"] = [{"status": "eligible", "count": True}]
        with self.assertRaises(m.PoolStatusError):
            m.parse_status(json.dumps(payload).encode())
        payload = status_payload()
        payload["min_submitters"] = 0
        with self.assertRaises(m.PoolStatusError):
            m.parse_status(json.dumps(payload).encode())

    def test_aggregate_report_does_not_copy_row_content_or_addresses(self):
        report = m.parse_status(json.dumps(status_payload()).encode())
        encoded = json.dumps(report)
        self.assertNotIn("must never be copied", encoded)
        self.assertNotIn("0xmust-not-be-copied", encoded)
        self.assertNotIn('"rows": [', encoded)
        self.assertFalse(report["source"]["contributor_address_requested"])
        self.assertFalse(report["source"]["network_write_performed"])

    def test_response_byte_cap_is_enforced(self):
        with self.assertRaises(m.PoolStatusError):
            m.parse_status(b"x" * (m.MAX_RESPONSE_BYTES + 1))

    def test_write_once_refuses_overwrite(self):
        report = m.parse_status(json.dumps(status_payload()).encode())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            m.write_once(path, report)
            self.assertTrue(path.is_file())
            with self.assertRaises(m.PoolStatusError):
                m.write_once(path, report)


if __name__ == "__main__":
    unittest.main()
