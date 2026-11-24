"""Constructed negative controls; original online replay runs separately."""
import json
from pathlib import Path
import tempfile
import unittest
from falsum import phase5aj_cross_app_evidence as a


class CrossAppTests(unittest.TestCase):
    def test_known_contradiction(self):
        fields = {"verdict": "Secure", "vulnerability_count": 0,
                  "summary": "No code, configuration, or system description was provided to evaluate."}
        self.assertEqual(a.diagnostic(fields), "EXPLICIT_NO_EVIDENCE_CONTRADICTION")
        fields["vulnerability_count"] = False
        self.assertEqual(a.diagnostic(fields), "UNVERIFIED")

    def test_no_positive_clearance(self):
        for fields in [None, {}, {"verdict": "Secure", "vulnerability_count": 0,
                                   "summary": "The code looks good."},
                       {"verdict": "Needs changes", "vulnerability_count": 0,
                        "summary": "No code, configuration, or system description was provided to evaluate."}]:
            with self.subTest(fields=fields):
                self.assertEqual(a.diagnostic(fields), "UNVERIFIED")

    def test_duplicate_and_nonfinite_json(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}']:
            with self.assertRaises(a.AuditError):
                a.parse(raw)

    def test_source_lock_tamper(self):
        with tempfile.TemporaryDirectory() as path:
            root = Path(path)
            file = root / a.PROTOCOL
            file.parent.mkdir()
            file.write_bytes((a.ROOT / a.PROTOCOL).read_bytes() + b"\n")
            with self.assertRaisesRegex(a.AuditError, "lock changed"):
                a.protocol(root)

    def fixture(self):
        ident = "0x" + "a" * 64
        receipt = dict(receipt_hash=ident, intent=a.INTENT, epoch_id=1,
                       miner="settlement-1", amount_uusdc="10000")
        purchase = dict(kind="purchase", intent=a.INTENT, miner_id="registration-1",
                        amount_uusdc=10000, receipt=receipt)
        decision = dict(kind="decision", input=dict(name="case.sol"), verdict="SHIP",
                        receipts=[ident], evidence=[dict(intent=a.INTENT, ok=True,
                                  miner_id="registration-1", result={})])
        archived = dict(total=1, settled=1, pending=0, mismatch=0, other=0,
                        receipts=[dict(receipt_hash=ident, status="SETTLED", mismatch=[],
                                       intent=a.INTENT, epoch_id=1, miner_id="settlement-1",
                                       usdc=10000)])
        expected = dict(decisions=1, security_answers=1, security_explicit_failures=0,
                        security_absent_without_explicit_failure=0, all_purchases=1,
                        all_errors=0, ship_without_security_answer=0, fix=0, hold=0,
                        ship=1, ship_with_known_planted_bug=1)
        return [purchase, decision], archived, {"case.sol": {"bug": True}}, expected

    def run_fixture(self, rows, archived, labels, expected):
        raw = ("\n".join(json.dumps(row) for row in rows) + "\n").encode()
        return a.ledger_audit(raw, archived, labels, "planted", expected)

    def test_separate_miner_namespaces(self):
        result = self.run_fixture(*self.fixture())
        self.assertEqual(result["archived_receipts_matched"], 1)
        self.assertFalse(result["live_settlement_verified"])
        self.assertFalse(result["security_clearance_granted"])

    def test_wrong_settlement_miner(self):
        rows, archive, labels, expected = self.fixture()
        archive["receipts"][0]["miner_id"] = rows[0]["miner_id"]
        with self.assertRaisesRegex(a.AuditError, "receipt identity"):
            self.run_fixture(rows, archive, labels, expected)

    def test_receipt_reuse_and_orphan(self):
        rows, archive, labels, expected = self.fixture()
        with self.assertRaises(a.AuditError):
            self.run_fixture([rows[0], rows[0], rows[1]], archive, labels, expected)
        with self.assertRaises(a.AuditError):
            self.run_fixture(rows[:1], archive, labels, expected)

    def test_receipt_intent_and_amount_mismatch(self):
        for field, value in [("intent", "CODE_REVIEW_GENERAL"), ("usdc", 10001)]:
            rows, archive, labels, expected = self.fixture()
            archive["receipts"][0][field] = value
            with self.assertRaises(a.AuditError):
                self.run_fixture(rows, archive, labels, expected)

    def test_failed_answer_cannot_borrow_receipt(self):
        rows, archive, labels, expected = self.fixture()
        rows[1]["evidence"][0]["ok"] = False
        with self.assertRaises(a.AuditError):
            self.run_fixture(rows, archive, labels, expected)

    def test_missing_case_cannot_be_omitted(self):
        rows, archive, labels, expected = self.fixture()
        labels["other.sol"] = {"bug": True}
        with self.assertRaises(a.AuditError):
            self.run_fixture(rows, archive, labels, expected)

    def test_explicit_failure_is_not_missing_record(self):
        empty = dict(total=0, settled=0, pending=0, mismatch=0, other=0, receipts=[])
        labels = {"case.sol": {"bug": True}}
        decision = dict(kind="decision", input=dict(name="case.sol"), verdict="HOLD",
                        receipts=[], evidence=[])
        expected = dict(decisions=1, security_answers=0, security_explicit_failures=0,
                        security_absent_without_explicit_failure=1, all_purchases=0,
                        all_errors=0, ship_without_security_answer=0, fix=0, hold=1,
                        ship=0, ship_with_known_planted_bug=0)
        r = self.run_fixture([decision], empty, labels, expected)
        self.assertEqual(r["cases"][0]["security_answer_availability"], "NO_ANSWER_RECORD")
        decision["evidence"] = [dict(intent=a.INTENT, ok=False)]
        expected.update(security_absent_without_explicit_failure=0,
                        security_explicit_failures=1, all_errors=1)
        r = self.run_fixture([dict(kind="error", intent=a.INTENT), decision],
                             empty, labels, expected)
        self.assertEqual(r["cases"][0]["security_answer_availability"], "RECORDED_FAILURE")


if __name__ == "__main__":
    unittest.main()
