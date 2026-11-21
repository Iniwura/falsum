"""Constructed adversarial checks; not additional genuine Miner observations."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5ab_original_receipt_comparability as audit
from falsum.phase4l_external_receipt_evidence import git_blob_sha
from falsum.phase5m_real_source_sensitive_model import ROOT


def constructed(*, receipt="SECURITY_REVIEW_GENERAL", request=None,
                miner="77003", status=200):
    if request is None:
        request = {"intent": "SECURITY_REVIEW_GENERAL",
                   "params": {"target": "example constructed security snippet"}}
    record = {
        "paid": True, "charged": True,
        "payment": {"success": True},
        "status": status, "request": deepcopy(request),
    }
    if status == 200:
        record.update({
            "receipt": {"intent": receipt, "receipt_hash": "0x" + "a" * 64},
            "body": {"miner_id": miner, "signal_hash": "0x" + "b" * 64}
        })
    return record


def row(document):
    return audit.inspect(document, path="ROUTED/constructed.json",
                         original_blob_sha1="c" * 40)


class OriginalReceiptComparabilityTests(unittest.TestCase):
    def test_original_preimplementation_contract_and_source_roster(self):
        policy = audit.frozen()
        self.assertEqual(git_blob_sha((ROOT / audit.LOCK).read_bytes()), audit.LOCK_BLOB)
        self.assertEqual(len(policy["capture_sources"]), 12)
        self.assertEqual(len({x["git_blob_sha1"] for x in policy["capture_sources"]}), 12)
        self.assertEqual(policy["expected_genuine_byte_identical_same_canonical_request_multi_miner_pairs"], 0)

    def test_only_explicit_routed_request_with_matching_receipt_qualifies(self):
        r = row(constructed())
        self.assertEqual(r["capture_intent_provenance_class"], audit.KIND_ROUTED)
        self.assertIsNotNone(r["canonical_request_sha256"])
        self.assertFalse(r["original_source_verified_by_git_blob"])
        self.assertFalse(r["actual_paid_settlement_independently_verified"])

    def test_directory_label_cannot_make_direct_provider_request_canonical(self):
        direct = {"method": "GET", "endpoint": "/query",
                  "payload": {"pkg": "lodash", "ver": "4.17.15"}}
        r = audit.inspect(constructed(request=direct),
                          path="SECURITY_REVIEW_GENERAL/constructed.json",
                          original_blob_sha1="c" * 40)
        self.assertEqual(r["capture_intent_provenance_class"], audit.KIND_DIRECT)
        self.assertFalse(r["request_has_canonical_routed_schema"])
        self.assertIsNone(r["canonical_request_sha256"])
        self.assertIsNone(r["request_explicit_intent"])

    def test_wrong_receipt_intent_cannot_be_compared_as_canonical(self):
        record = constructed(receipt="FACT_CHECK_GENERAL")
        r = row(record)
        self.assertEqual(r["capture_intent_provenance_class"], audit.KIND_DIFFERENT)
        self.assertIsNone(r["canonical_request_sha256"])
        self.assertEqual(r["request_explicit_intent"], "SECURITY_REVIEW_GENERAL")

    def test_direct_payload_intent_is_not_canonical_routed_request(self):
        doc = constructed(receipt="FACT_CHECK", request={
            "method": "POST", "endpoint": "/v1/intent",
            "payload": {"intent": "SECURITY_REVIEW", "input": {"code": "x"}}
        })
        r = row(doc)
        self.assertEqual(r["capture_intent_provenance_class"], audit.KIND_DIFFERENT)
        self.assertEqual(r["request_explicit_intent"], "SECURITY_REVIEW")

    def test_improper_canonical_params_fail_exact_envelope(self):
        for obj in (
            {"intent": "SECURITY_REVIEW_GENERAL", "params": {}},
            {"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": ""}},
            {"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": 1}},
            {"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": "x"}, "paid": True},
            {"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": "x", "other": "x"}},
            {"intent": "SECURITY_REVIEW", "params": {"target": "x"}},
        ):
            with self.subTest(obj=obj):
                r = row(constructed(request=obj))
                self.assertNotEqual(r["capture_intent_provenance_class"], audit.KIND_ROUTED)
                self.assertIsNone(r["canonical_request_sha256"])

    def test_status_500_has_no_eligible_receipt_even_if_paid_flag_true(self):
        record = constructed(status=500)
        r = row(record)
        self.assertEqual(r["capture_intent_provenance_class"], audit.KIND_FAILED)
        self.assertIsNone(r["receipt_intent"])
        self.assertIsNone(r["canonical_request_sha256"])

    def test_failed_observation_cannot_smuggle_success_receipt(self):
        record = constructed(status=500)
        record["receipt"] = {"intent": audit.CANONICAL}
        with self.assertRaises(ValueError):
            row(record)

    def test_false_payment_flag_or_incomplete_success_receipt_fails_closed(self):
        cases = [
            ("paid", False), ("charged", False), ("payment", {"success": False}),
            ("status", 201), ("receipt", None), ("body", None),
        ]
        for k, v in cases:
            with self.subTest(key=k):
                data = constructed()
                data[k] = v
                with self.assertRaises(ValueError):
                    row(data)

    def test_missing_request_and_invalid_miner_identity_fail(self):
        doc = constructed()
        doc["request"] = None
        with self.assertRaises(ValueError):
            row(doc)
        doc = constructed()
        doc["body"]["miner_id"] = "other-party"
        with self.assertRaises(ValueError):
            row(doc)

    def test_exact_comparability_requires_two_reported_miners_on_identical_requests(self):
        a = row(constructed(miner="1"))
        b = row(constructed(miner="2"))
        pair = audit.same_request_candidates([a, b])
        self.assertEqual(len(pair), 1)
        self.assertEqual(pair[0]["reported_distinct_miner_ids"], ["1", "2"])
        self.assertFalse(pair[0]["provider_owner_independence_verified"])
        self.assertFalse(pair[0]["fair_independent_network_ranking_proved"])
        # Two reports from a single Miner, however many times repeated, are not multi-Miner evidence.
        c = row(constructed(miner="1"))
        self.assertEqual(audit.same_request_candidates([a, c]), [])
        # Same semantic target does not override changed canonical input bytes.
        diff = constructed(miner="2")
        diff["request"]["params"]["target"] = "an unrelated input"
        self.assertEqual(audit.same_request_candidates([a, row(diff)]), [])

    def test_local_constructed_capture_cannot_be_promoted_into_original_git_observation(self):
        doc = constructed()
        dumped = json.dumps(doc, sort_keys=True).encode()
        original = audit.frozen()["capture_sources"][0]
        self.assertNotEqual(git_blob_sha(dumped), original["git_blob_sha1"])
        with self.assertRaises(ValueError):
            audit.study(download=lambda _url: dumped)

    def test_freeze_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as dir:
            root = Path(dir)
            lock = root / audit.LOCK
            lock.parent.mkdir(parents=True)
            lock.write_bytes((ROOT / audit.LOCK).read_bytes() + b" ")
            with self.assertRaises(ValueError):
                audit.frozen(root)


if __name__ == "__main__":
    unittest.main()
