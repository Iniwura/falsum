"""Phase 4L tests: fabricated paid captures only; no third-party bodies copied."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum.phase4l_external_receipt_evidence import (
    COMMIT, EXCLUDED_MINERS, SOURCE_BASE, SPECS, STATUS, EvidenceError,
    _input_for, git_blob_sha, inspect_fixture, main, report
)

TARGET = ("diff --git a/src/users.js b/src/users.js\n"
          "+db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\")\n"
          "+eval(req.body.expr)")
SENTINEL = "731001"


def make(role: str, target: str = TARGET) -> dict:
    spec = SPECS[role]
    if role == "routed_security":
        req = {"intent": "SECURITY_REVIEW_GENERAL", "params": {"target": target}}
        result = [{"ghsa_id": f"GHSA-0000-0000-{i:04d}"} for i in range(100)]
    elif role == "direct_verity":
        req = {"method": "POST", "endpoint": "/v1/intent",
               "payload": {"intent": "SECURITY_REVIEW", "input": {"code": target}}}
        result = {"answer": {"findings": [
            {"rule_id": "sql-injection-risk", "severity": "high"},
            {"rule_id": "dynamic-code-execution", "severity": "high"}]}}
    else:
        req = {"intent": "CODE_REVIEW_GENERAL", "params": {"code": target}}
        result = {"verdict": "Request changes",
                  "findings": ["SQL Injection requires parameterized queries",
                               "Code Injection risk from dynamic eval"],
                  "summary": "Found concerns"}
    return {
        "request": req, "paid": True, "ok": True, "charged": True,
        "status": 200, "payment": {"success": True, "payer": "SENSITIVE-PAYER"},
        "body": {"miner_id": spec["miner_id"], "result_shape": spec["shape"],
                 "result": result, "signal_hash": "0x" + "a" * 64},
        "receipt": {"miner": "999999", "intent": "FACT_CHECK_GENERAL",
                    "receipt_hash": "0x" + "b" * 64, "payer": "SENSITIVE-PAYER"},
        "bodyText": "SENSITIVE-RAW-RESPONSE",
    }


def fbytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def source_pack(changes=None):
    fixtures = {role: make(role) for role in SPECS}
    if changes:
        changes(fixtures)
    payload = {r: fbytes(x) for r, x in fixtures.items()}
    specs = {r: dict(SPECS[r], blob=git_blob_sha(raw)) for r, raw in payload.items()}
    url_to_bytes = {SOURCE_BASE + specs[r]["path"]: raw for r, raw in payload.items()}
    def fetch(url):
        if url not in url_to_bytes:
            raise ValueError("wrong URL")
        return url_to_bytes[url]
    return specs, fetch, fixtures


class ExternalSourceTests(unittest.TestCase):
    def test_exact_pins_and_no_owner_miner(self):
        self.assertEqual(COMMIT, "99d2e3c93890a8fc083947bde4f21217516b7a5f")
        self.assertEqual(set(SPECS), {"routed_security", "direct_verity", "routed_code"})
        self.assertEqual(EXCLUDED_MINERS, {"731001"})
        self.assertNotIn(SENTINEL, json.dumps(SPECS))
        self.assertEqual([SPECS[r]["miner_id"] for r in SPECS], ["77003", "5530", "302"])
        self.assertTrue(all(s["blob"] and len(s["blob"]) == 40 for s in SPECS.values()))

    def test_three_synthetic_same_diff_captures_not_trained_evaluator(self):
        specs, fetch, _ = source_pack()
        result = report(fetch, specs)
        self.assertEqual(result["status"], STATUS)
        self.assertEqual(result["captured_paid_response_records"], 3)
        self.assertEqual(len(result["comparison_roles"]), 3)
        self.assertTrue(result["cross_intent_chain_sight_not_ranking_candidate"])
        self.assertFalse(result["same_intent_equal_router_comparison"])
        self.assertFalse(result["trained_evaluator_improvement_established"])
        self.assertFalse(result["receipt_cryptographic_or_onchain_verification_established"])
        self.assertFalse(result["excluded_miner_answers_loaded_or_scored"])
        self.assertEqual(result["quality_gold_labels"], 0)
        self.assertEqual({c["request_input_sha256"] for c in result["comparison_roles"]},
                         {result["same_request_input_sha256"]})
        self.assertEqual(
            [r["observed_response_structure"] for r in result["comparison_roles"]],
            ["100-item-GHSA-feed-not-target-specific-review",
             "two-target-relevant-heuristic-rule-identifiers",
             "target-relevant-findings-in-different-intent"])
        self.assertEqual(
            [r["request_intent"] for r in result["comparison_roles"]],
            ["SECURITY_REVIEW_GENERAL", "SECURITY_REVIEW", "CODE_REVIEW_GENERAL"])
        self.assertFalse(any(r["receipt_miner_field_matches_body_miner_id"]
                             for r in result["comparison_roles"]))

    def test_no_private_payments_or_body_text_in_report(self):
        specs, fetch, _ = source_pack()
        payload = json.dumps(report(fetch, specs))
        for private in ("SENSITIVE-PAYER", "SENSITIVE-RAW-RESPONSE", TARGET,
                        "GHSA-0000-0000-0001", "finding_text"):
            self.assertNotIn(private, payload)
        self.assertNotIn("731001", json.dumps(report(fetch, specs)["comparison_roles"]))

    def test_incorrect_pinned_source_sha_fails_closed(self):
        specs, fetch, _ = source_pack()
        specs["direct_verity"]["blob"] = "0" * 40
        with self.assertRaisesRegex(EvidenceError, "blob"):
            report(fetch, specs)

    def test_excluded_miner_refused_even_if_blob_recomputed(self):
        def change(fixtures):
            fixtures["routed_security"]["body"]["miner_id"] = SENTINEL
        specs, fetch, _ = source_pack(change)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)
        specs, fetch, _ = source_pack()
        specs["direct_verity"]["miner_id"] = SENTINEL
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_missing_role_and_unapproved_role_forbidden(self):
        specs, fetch, _ = source_pack()
        specs.pop("routed_security")
        with self.assertRaisesRegex(EvidenceError, "roles"):
            report(fetch, specs)
        specs, fetch, _ = source_pack()
        specs["731001_owned"] = dict(specs["routed_security"])
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_unrelated_input_cannot_be_compared_as_same_diff(self):
        def change(fixtures):
            fixtures["routed_code"]["request"]["params"]["code"] = TARGET + "\n+unrelated change"
        specs, fetch, _ = source_pack(change)
        with self.assertRaisesRegex(EvidenceError, "same exact input"):
            report(fetch, specs)

    def test_wrong_intent_cannot_be_laundered_as_security_review(self):
        def change(fixtures):
            fixtures["routed_code"]["request"]["intent"] = "SECURITY_REVIEW_GENERAL"
        specs, fetch, _ = source_pack(change)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)
        def change2(fixtures):
            fixtures["direct_verity"]["request"]["payload"]["intent"] = "SECURITY_REVIEW_GENERAL"
        specs, fetch, _ = source_pack(change2)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_unpaid_or_failed_payment_is_not_paid_capture(self):
        for mutation in ("paid", "ok", "charged"):
            def change(fixtures):
                fixtures["direct_verity"][mutation] = False
            specs, fetch, _ = source_pack(change)
            with self.assertRaises(EvidenceError):
                report(fetch, specs)
        def change2(fixtures):
            fixtures["routed_security"]["payment"]["success"] = False
        specs, fetch, _ = source_pack(change2)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_100_advisories_are_not_a_security_review(self):
        def change(fixtures):
            fixtures["routed_security"]["body"]["result"] = {"summary": "unrelated"}
        specs, fetch, _ = source_pack(change)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_missing_verity_findings_rejected(self):
        def change(fixtures):
            fixtures["direct_verity"]["body"]["result"]["answer"]["findings"][1]["rule_id"] = "unknown"
        specs, fetch, _ = source_pack(change)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_missing_chain_sight_risks_rejected(self):
        def change(fixtures):
            fixtures["routed_code"]["body"]["result"]["findings"] = ["No issues"]
        specs, fetch, _ = source_pack(change)
        with self.assertRaises(EvidenceError):
            report(fetch, specs)

    def test_receipt_fields_are_observations_not_auto_trusted_proof(self):
        specs, fetch, _ = source_pack()
        rows = report(fetch, specs)["comparison_roles"]
        self.assertFalse(any(r["receipt_intent_field_matches_request_intent"] for r in rows))
        self.assertTrue(all(not r["receipt_metadata_semantics_or_chain_validated"] for r in rows))
        self.assertTrue(all(r["accuracy_score"] is None and r["expert_gold_label"] is None
                            and not r["training_or_ranking_use_allowed"] for r in rows))

    def test_cli_refuses_overwrite_and_never_contacts_external_source_when_mocked(self):
        specs, fetch, _ = source_pack()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "public-aggregate.json"
            with patch("falsum.phase4l_external_receipt_evidence.report",
                       return_value=report(fetch, specs)):
                self.assertEqual(main(["--out", str(path)]), 0)
            self.assertTrue(path.is_file())
            self.assertNotIn("SENSITIVE", path.read_text())
            with self.assertRaises(SystemExit):
                main(["--out", str(path)])

    def test_missing_network_source_does_not_publish_false_evidence(self):
        def offline(url):
            raise OSError("synthetic source unreachable, private value")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "should-not-exist.json"
            with patch("falsum.phase4l_external_receipt_evidence.fetch_bytes", offline):
                with self.assertRaises(SystemExit):
                    main(["--out", str(path)])
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
