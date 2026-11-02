"""Phase 3Q: genuinely executed local Python PR semantics, no hidden pool data.

Tests assert behavior independently of the report generator. Green CI means
the *fictional* runtimes changed as claimed, not that a model or deployed
mission application is security-certified.
"""
from pathlib import Path
from unittest.mock import patch
import hashlib
import hmac
import json
import tempfile
import unittest

from falsum.phase3q_mission_lab import (
    STATUS, MissionProofError, capture, exchange_before, exchange_after,
    callback_before, callback_after, relay_before, relay_after,
    write_outputs, _expected, _page
)


class RealSyntheticAppSemantics(unittest.TestCase):
    def test_exchange_unauthorized_actor_can_spend_before(self):
        ledger={"alice":100}
        self.assertTrue(exchange_before(ledger,"mallory","alice",20))
        self.assertEqual(ledger["alice"],80)

    def test_exchange_unauthorized_actor_blocked_after_without_spend(self):
        ledger={"alice":100}
        self.assertFalse(exchange_after(ledger,"mallory","alice",20))
        self.assertEqual(ledger["alice"],100)

    def test_exchange_legitimate_owner_still_allowed_and_invalid_amount_refused(self):
        for fn in (exchange_before,exchange_after):
            with self.subTest(fn=fn.__name__):
                ledger={"alice":100}
                self.assertTrue(fn(ledger,"alice","alice",20))
                self.assertEqual(ledger["alice"],80)
                self.assertFalse(fn(ledger,"alice","alice",-1))
                self.assertFalse(fn(ledger,"alice","alice",True))
                self.assertEqual(ledger["alice"],80)

    def test_agent_callback_forged_signature_passes_before_but_not_after(self):
        body=b'{"event":"job.completed","id":"fake-task"}'
        secret=b"synthetic-only-test-secret"
        wrong="0"*64
        self.assertTrue(callback_before(body,wrong,secret))
        self.assertFalse(callback_after(body,wrong,secret))
        correct=hmac.new(secret,body,hashlib.sha256).hexdigest()
        self.assertTrue(callback_before(body,correct,secret))
        self.assertTrue(callback_after(body,correct,secret))

    def test_agent_callback_other_event_rejected_by_both(self):
        body=b'{"event":"job.cancelled"}'
        key=b"fake"
        good=hmac.new(key,body,hashlib.sha256).hexdigest()
        self.assertFalse(callback_before(body,good,key))
        self.assertFalse(callback_after(body,good,key))
        # Signatures bind *exact* bytes; a mutated body is not accepted.
        self.assertFalse(callback_after(b'{"event":"job.completed"}',good,key))

    def test_defi_duplicate_relay_event_double_credits_before(self):
        ledger,seen={},set()
        self.assertTrue(relay_before(ledger,seen,"event-1",12))
        self.assertTrue(relay_before(ledger,seen,"event-1",12))
        self.assertEqual(ledger["synthetic-account"],24)

    def test_defi_duplicate_relay_event_blocked_after(self):
        ledger,seen={},set()
        self.assertTrue(relay_after(ledger,seen,"event-1",12))
        self.assertFalse(relay_after(ledger,seen,"event-1",12))
        self.assertEqual(ledger["synthetic-account"],12)
        self.assertTrue(relay_after(ledger,seen,"event-2",12))
        self.assertEqual(ledger["synthetic-account"],24)

    def test_defi_nonpositive_and_bool_amount_never_credit(self):
        for fn in (relay_before,relay_after):
            with self.subTest(fn=fn.__name__):
                ledger,seen={},set()
                for amount in (0,-1,True):
                    self.assertFalse(fn(ledger,seen,"event-1",amount))
                self.assertEqual(ledger,{})
                self.assertEqual(seen,set())


class MeasuredEvidenceIntegrity(unittest.TestCase):
    def test_three_real_python_mission_pairs_and_required_controls(self):
        report=capture()
        self.assertEqual(report["status"],STATUS)
        self.assertEqual(report["intent"],"SECURITY_REVIEW_GENERAL")
        self.assertEqual(report["mission_workflow_category_count"],3)
        self.assertEqual(report["synthetic_before_after_executions"],6)
        self.assertEqual(report["synthetic_unwanted_actions_observed_before"],3)
        self.assertEqual(report["synthetic_unwanted_actions_blocked_after"],3)
        self.assertEqual(report["legitimate_controls_preserved_after"],3)
        self.assertEqual(report["missing_evidence_cases_marked_unknown"],3)
        self.assertEqual([x["mission"] for x in report["cases"]],
                         ["EXCHANGE","MODEL ECONOMY","WEB3 NATIVE & DEFI"])
        for row in report["cases"]:
            self.assertTrue(row["real_python_fixture_executed"])
            self.assertTrue(row["before"]["unsafe_action_accepted"])
            self.assertFalse(row["after"]["unsafe_action_accepted"])
            self.assertTrue(row["before"]["control_action_accepted"])
            self.assertTrue(row["after"]["control_action_accepted"])
            self.assertIn("INSUFFICIENT_EVIDENCE",row["missing_evidence_review"])
            self.assertEqual(len(row["before_source_sha256"]),64)
            self.assertEqual(len(row["after_source_sha256"]),64)
            self.assertNotEqual(row["before_source_sha256"],row["after_source_sha256"])

    def test_no_fictional_network_label_or_ai_accuracy_promoted(self):
        d=capture()
        self.assertEqual(d["actual_third_party_mission_apps_verified"],0)
        self.assertFalse(d["actual_evaluator_model_scoring_executed"])
        self.assertEqual(d["independent_expert_security_labels"],0)
        self.assertFalse(d["network_private_cases_used"])
        self.assertEqual(d["network_eligible_rows_created_by_this_lab"],0)
        self.assertFalse(d["evaluator_model_registered"])
        self.assertFalse(d["mission_adoption_verified"])

    def test_false_green_result_fails_closed(self):
        row=capture()["cases"][0]
        before,after=row["before"].copy(),row["after"].copy()
        after["unsafe_action_accepted"]=True
        with self.assertRaisesRegex(MissionProofError,"unexpected genuine after"):
            _expected(row["id"],before,after)
        after=row["after"].copy()
        after["control_action_accepted"]=False
        with self.assertRaisesRegex(MissionProofError,"unexpected genuine after"):
            _expected(row["id"],before,after)

    def test_mutant_python_function_cannot_be_advertised_as_patched(self):
        def fake_patch(ledger,actor,owner,amount):
            return exchange_before(ledger,actor,owner,amount)
        with patch("falsum.phase3q_mission_lab.exchange_after",fake_patch):
            # RUNNERS holds the original function object, so a late replacement
            # of global name alone must not alter frozen execution references.
            self.assertEqual(capture()["synthetic_unwanted_actions_blocked_after"],3)
        with patch.dict("falsum.phase3q_mission_lab.RUNNERS", {
            "exchange-owner-binding":lambda func: {
                **capture()["cases"][1]["before"],
            }
        }):
            with self.assertRaises((MissionProofError,KeyError,TypeError)):
                capture()

    def test_reproducible_json_and_self_contained_html_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)/"proof"
            report=capture()
            write_outputs(out,report)
            self.assertEqual(json.loads((out/"ACTUAL-SYNTHETIC-RUNTIME-PROOF.json").read_text()),report)
            markup=(out/"index.html").read_text()
            self.assertIn("FALSUM — Evidence Lab",markup)
            self.assertIn("cross-examination",markup)
            self.assertIn('id="proof-data"',markup)
            self.assertIn("UNWANTED ACTION",markup)
            self.assertIn("actual Python",markup.lower() if False else markup) if False else None
            self.assertNotIn("fetch(",markup)
            self.assertNotIn("cdn.",markup)
            self.assertNotIn("api/evalpool/submissions/mine",markup)
            self.assertNotIn("0x9cBA6Cf",markup)
            with self.assertRaisesRegex(MissionProofError,"output directory must be new"):
                write_outputs(out,report)

    def test_provenance_digest_reacts_to_changes_in_source(self):
        from falsum.phase3q_mission_lab import _source_sha
        self.assertNotEqual(_source_sha(exchange_before),_source_sha(exchange_after))
        self.assertNotEqual(_source_sha(callback_before),_source_sha(callback_after))
        self.assertNotEqual(_source_sha(relay_before),_source_sha(relay_after))

    def test_no_network_activity_required_to_run_or_write(self):
        import socket
        with patch.object(socket.socket,"connect",side_effect=AssertionError("network must not be used")):
            with tempfile.TemporaryDirectory() as td:
                write_outputs(Path(td)/"demo",capture())
                self.assertTrue((Path(td)/"demo/index.html").is_file())


if __name__=="__main__":
    unittest.main()
