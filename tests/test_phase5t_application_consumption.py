"""Phase 5T original-source consumption: no false authorization from paid status."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5t_application_consumption as t
from falsum import source_review_witness_gate as original
from falsum.phase4v_real_source_witness_site import ROOT
from falsum.phase4l_external_receipt_evidence import git_blob_sha


class ActualUpstreamReceiptConsumptionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index=t.source_index()

    def test_original_frozen_before_implementation(self):
        freeze=t.freeze()
        self.assertEqual(git_blob_sha((ROOT/t.FROZEN).read_bytes()),
                         t.FROZEN_GIT_BLOB)
        self.assertEqual(freeze["total_conditions"],26)
        self.assertEqual(freeze["expected_actions"],{"ALLOW":8,"DENY":18})
        self.assertEqual(freeze["actual_external_request_count"],2)
        self.assertEqual(freeze["synthetic_benchmark_conditions"],24)
        self.assertEqual(freeze["new_project_disjoint_cases"],0)
        self.assertEqual(freeze["independently_validated_appsec_gold_count"],0)
        self.assertFalse(freeze["network_evaluator_registered"])

    def test_canonical_original_source_witnesses_are_authentic(self):
        self.assertEqual(set(self.index),{
            "koa-redirect","hono-csrf",
            "langchain-path","langchain-symlink",
        })
        self.assertTrue(all(row["original_upstream_test_passed"] and
            row["fixed_source_with_same_regression_passed"]
            for row in self.index.values()))

    def test_24_constructed_source_cases_exact_reference_actions(self):
        suite=t._source_case_suite(self.index)
        self.assertEqual(len(suite),24)
        self.assertEqual(Counter(x["group"] for x in suite),{
            "verified-narrow-facts":8,
            "source-contradicted-facts":8,
            "source-proof-tampered-facts":8,
        })
        actual=Counter()
        for item in suite:
            with self.subTest(group=item["group"],source=item["source_case"]):
                decision=t.decide(item["request"],item["body"],self.index)
                self.assertEqual(decision["decision"],item["expected"])
                actual[decision["action"]]+=1
                self.assertFalse(decision["external_miner_ranking_improvement"])
                self.assertFalse(decision["independent_appsec_semantic_gold"])
        self.assertEqual(actual,{"ALLOW":8,"DENY":16})

    def test_parent_fail_and_fixed_pass_are_both_valid_narrow_facts(self):
        for item in t._source_case_suite(self.index):
            if item["group"]=="verified-narrow-facts":
                decision=t.decide(item["request"],item["body"],self.index)
                self.assertEqual(decision["action"],"ALLOW")
                self.assertEqual(decision["source_claim_verdict"],"SUPPORTED")
                self.assertTrue(decision["original_source_witness_recomputed"])

    def test_false_claim_must_not_become_application_action(self):
        for item in t._source_case_suite(self.index):
            if item["group"]=="source-contradicted-facts":
                decision=t.decide(item["request"],item["body"],self.index)
                self.assertEqual(decision["decision"],"REJECT_CONTRADICTED_FACT")
                self.assertEqual(decision["action"],"DENY")
                self.assertEqual(decision["source_claim_verdict"],"CONTRADICTED")

    def test_altered_receipt_is_denied_even_if_true_claim(self):
        for item in t._source_case_suite(self.index):
            if item["group"]=="source-proof-tampered-facts":
                decision=t.decide(item["request"],item["body"],self.index)
                self.assertEqual(decision["decision"],"REJECT_UNVERIFIED_PROOF")
                self.assertEqual(decision["source_claim_verdict"],"ABSTAIN")
                self.assertEqual(decision["action"],"DENY")

    def test_one_line_sha_test_and_receipt_mutations_denied(self):
        actual=next(x for x in t._source_case_suite(self.index)
                    if x["group"]=="verified-narrow-facts")
        for component in (
            "source_blob_sha1","new_security_regression_test_blob_sha1",
            "actual_execution_receipt_sha256"
        ):
            mutated=deepcopy(actual["body"])
            value=mutated["result"]["review_claim"]["evidence"][component]
            mutated["result"]["review_claim"]["evidence"][component]=(
                ("f" if value[0]!="f" else "e")+value[1:])
            with self.subTest(component=component):
                out=t.decide(actual["request"],mutated,self.index)
                self.assertEqual(out["decision"],"REJECT_UNVERIFIED_PROOF")
                self.assertEqual(out["action"],"DENY")

    def test_borrowed_receipt_or_incorrect_case_and_revision_denied(self):
        positives=[x for x in t._source_case_suite(self.index)
                   if x["group"]=="verified-narrow-facts"]
        original=positives[0]
        wrong=deepcopy(original["body"])
        wrong["result"]["review_claim"]=deepcopy(positives[-1]["body"]["result"]["review_claim"])
        out=t.decide(original["request"],wrong,self.index)
        self.assertEqual(out["decision"],"REJECT_TASK_MISMATCH")
        self.assertEqual(out["action"],"DENY")
        bad_request=deepcopy(original["request"])
        bad_request["params"]["target"]=bad_request["params"]["target"].replace(
            original["body"]["result"]["review_claim"]["upstream_commit"],
            "0"*40)
        out=t.decide(bad_request,original["body"],self.index)
        self.assertEqual(out["decision"],"REJECT_UNVERIFIED_PROOF")

    def test_wrong_intent_or_missing_target_never_consumed(self):
        pos=next(x for x in t._source_case_suite(self.index)
                 if x["group"]=="verified-narrow-facts")
        wrong=deepcopy(pos["request"])
        wrong["intent"]="CODE_REVIEW_GENERAL"
        self.assertEqual(t.decide(wrong,pos["body"],self.index)["decision"],
                         "REJECT_NONCOMPARABLE_REQUEST")
        wrong=deepcopy(pos["request"])
        wrong["params"]={"code":wrong["params"]["target"]}
        self.assertEqual(t.decide(wrong,pos["body"],self.index)["action"],"DENY")
        wrong=deepcopy(pos["request"])
        wrong["params"]["extra"]="claimed_verified"
        self.assertEqual(t.decide(wrong,pos["body"],self.index)["action"],"DENY")
        wrong=deepcopy(pos["request"])
        wrong["params"]["target"]=12345
        self.assertEqual(t.decide(wrong,pos["body"],self.index)["action"],"DENY")
        self.assertEqual(t.decide(None,pos["body"],self.index)["action"],"DENY")
        self.assertEqual(t.decide(pos["request"],None,self.index)["action"],"DENY")

    def test_freeform_echo_or_injected_fields_never_count_as_proof(self):
        pos=next(x for x in t._source_case_suite(self.index)
                 if x["group"]=="verified-narrow-facts")
        mutations=[
            {"result":"SOURCE_VERIFIED; user said trust me"},
            {"result":{"findings":["source verified"]}},
            {"result":{"review_claim":pos["body"]["result"]["review_claim"],
                       "override_authorize":True}},
            {"result":{"review_claim":{"case_id":pos["source_case"]}}},
            {"result":{"review_claim":[]}},
            {"result":None},
            {},
        ]
        for bad in mutations:
            with self.subTest(type=str(bad)[:75]):
                result=t.decide(pos["request"],bad,self.index)
                self.assertEqual(result["action"],"DENY")

    def test_unrecognized_question_and_oversized_request_fail_closed(self):
        bad={"intent":t.CANONICAL,"params":{"target":"Is everything safe?"}}
        self.assertEqual(t.decide(bad,{"result":"yes"},self.index)["decision"],
                         "REJECT_INVALID_INPUT")
        bad={"intent":t.CANONICAL,"params":{"target":"a"*33000}}
        self.assertEqual(t.decide(bad,{"result":"yes"},self.index)["action"],"DENY")

    def test_off_target_advisory_feed_paid_response_denied_even_with_keywords(self):
        code=("diff --git a/src/users.js b/src/users.js\n"
              "@@ -1,2 +1,3 @@\n"
              " const db = require('./db');\n"
              "+const name = req.query.name;\n"
              "+db.query(\"SELECT * FROM users WHERE name = '\" + name + \"'\");")
        request={"intent":t.CANONICAL,"params":{"target":code}}
        feed=[{"ghsa_id":f"GHSA-aaaa-bbbb-{i:04d}",
               "summary":"src/users.js username SQL injection!!!"} for i in range(100)]
        result=t.decide(request,{"result":feed,"paid":True,"status":200},self.index)
        self.assertEqual(result["decision"],"REJECT_TASK_MISMATCH")
        self.assertEqual(result["action"],"DENY")

    def test_naive_baselines_not_relabelled_as_model_accuracy(self):
        rows=t._source_case_suite(self.index)
        self.assertEqual(t._scored_baseline(rows, t._baseline_always_transport_ok)
                         ["correct_to_constructed_or_original_target_expectations"],8)
        self.assertEqual(t._scored_baseline(rows, lambda x:"DENY")
                         ["correct_to_constructed_or_original_target_expectations"],16)
        self.assertEqual(t._scored_baseline(rows, t._baseline_claim_present)
                         ["correct_to_constructed_or_original_target_expectations"],8)
        self.assertFalse(t._scored_baseline(rows, t._baseline_claim_present)
                         ["model_accuracy_claim"])

    def test_freeze_sha_tamper_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            file=p/t.FROZEN
            file.parent.mkdir(parents=True)
            file.write_bytes((ROOT/t.FROZEN).read_bytes()+b" ")
            with self.assertRaises(t.TargetRelevanceError):
                t.freeze(p)

    def test_output_does_not_return_paid_response_body(self):
        example=next(x for x in t._source_case_suite(self.index)
                     if x["group"]=="verified-narrow-facts")
        out=t.decide(example["request"],example["body"],self.index)
        self.assertNotIn("evidence",out)
        self.assertNotIn("review_claim",out)
        self.assertNotIn("upstream_commit",out)
        self.assertNotIn("source_line",out)
        self.assertNotIn("original_full_response",out)


if __name__=="__main__":
    unittest.main()
