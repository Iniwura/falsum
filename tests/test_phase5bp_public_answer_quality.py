from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from falsum import phase5bp_public_answer_quality as m
from falsum import cli
from falsum.phase4l_external_receipt_evidence import git_blob_sha


def raw_capture(code: str, answer, *, verdict="likely", evidence=None, uncertainty=None):
    capture = {
        "request": {"method": "GET", "endpoint": "/query", "payload": {"intent": "SECURITY_REVIEW", "input": {"code": code}}},
        "paid": True,
        "status": 200,
        "body": {"result": {"answer": answer, "verdict": verdict,
                               "evidence": evidence or [], "uncertainty": uncertainty or []}},
    }
    raw = json.dumps(capture, sort_keys=True).encode()
    return m._provider_capture("fixture.json", git_blob_sha(raw), raw)


class PublicAnswerQualityTests(unittest.TestCase):
    def test_source_bound_structured_claims_and_actions_pass(self):
        code = "const rows = await db.query(\"SELECT * FROM users WHERE id = '\" + req.query.id + \"'\");\nres.send(String(eval(req.body.expr)));"
        answer = {"findings": [
            {"rule_id": "sql-injection-risk", "recommendation": "Use parameterized queries."},
            {"rule_id": "dynamic-code-execution", "recommendation": "Replace eval with an allow-list."},
        ]}
        evidence = [{"excerpt": code.split("\n")[0]}, {"excerpt": "res.send(String(eval(req.body.expr)));"}]
        row = raw_capture(code, answer, evidence=evidence, uncertainty=[{"code": "static"}])
        gate = row["comparisons"]["falsum_source_bound"]
        self.assertEqual(gate["action"], "BLOCK_OR_REMEDIATE")
        self.assertEqual(gate["quality_checks"], gate["quality_denominator"])

    def test_missing_action_does_not_become_a_block(self):
        code = "exec('ping -c 1 ' + req.query.host)"
        answer = "Verdict: vulnerable; exec('ping -c 1 ' + req.query.host) permits command injection."
        row = raw_capture(code, answer, verdict="vulnerable")
        gate = row["comparisons"]["falsum_source_bound"]
        self.assertEqual(gate["action"], "HOLD_FOR_REVIEW")
        self.assertFalse(gate["checks"]["action_or_uncertainty_complete"])

    def test_cross_target_evidence_is_rejected(self):
        code = "eval(req.body.expr)"
        answer = {"findings": [{"rule_id": "dynamic-code-execution", "recommendation": "Replace eval."}]}
        row = raw_capture(code, answer, evidence=[{"excerpt": "exec(req.query.host)"}], uncertainty=[{"code": "static"}])
        gate = row["comparisons"]["falsum_source_bound"]
        self.assertFalse(gate["checks"]["target_bound_evidence"])
        self.assertEqual(gate["action"], "HOLD_FOR_REVIEW")

    def test_clean_free_text_without_uncertainty_is_not_security_clearance(self):
        code = "db.query(\"SELECT * FROM users WHERE id = $1\", [req.params.id])"
        row = raw_capture(code, "Verdict: secure. No vulnerabilities detected.", verdict="secure")
        gate = row["comparisons"]["falsum_source_bound"]
        self.assertEqual(gate["action"], "HOLD_FOR_REVIEW")
        self.assertEqual(row["comparisons"]["verdict_only"]["action"], "CLEAN")

    def test_protocol_freezes_public_roster_and_non_gold_boundary(self):
        protocol = m.frozen_protocol()
        self.assertEqual(len(protocol["cases"]), 6)
        self.assertFalse(protocol["reference_policy"]["human_appsec_gold"])
        self.assertFalse(protocol["selection"]["answer_token_or_caller_classification_selects_result"])

    def test_installable_cli_dispatches_the_public_audit(self):
        with patch.object(m, "main", return_value=0) as entrypoint:
            self.assertEqual(cli.main(["audit-public-answer-quality", "--out", "judge.json"]), 0)
        entrypoint.assert_called_once_with(["--out", "judge.json"])


if __name__ == "__main__":
    unittest.main()
