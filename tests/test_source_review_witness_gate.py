"""Adversarial tests for FALSUM's typed source-regression witness evaluator.

These checks are CONSTRUCTED source-consistency tests, not a blind evaluation
of a trained or deployed Telegraph scoring model. No independent gold labels.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import source_review_witness_gate as g

ROOT=Path(__file__).resolve().parents[1]
INDEX_PATH=ROOT/"evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
SOURCE_PATH=ROOT/"data/phase4p-three-project-open-review-lock.json"
INDEX_RAW=INDEX_PATH.read_bytes()
SOURCE_RAW=SOURCE_PATH.read_bytes()


class SourceWitnessGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index=g.validated_index(INDEX_RAW,SOURCE_RAW)

    def test_actual_four_witness_indices_are_cited_not_human_gold(self):
        self.assertEqual(tuple(self.index),(
            "koa-redirect","hono-csrf","langchain-path","langchain-symlink"))
        self.assertEqual(len({r["repository"] for r in self.index.values()}),3)
        self.assertEqual(len({r["fixed_git_commit"] for r in self.index.values()}),4)
        self.assertEqual(g.sha(SOURCE_RAW),g.SOURCE_SHA256)
        self.assertEqual(g.ORIGINAL_FOUR_STAGE_PROOF_SHA256,
                         "e033e98fe8649f9b27a53f4e0f183bfc086257dc87f15ead0ba060aabf4fbf1c")
        for witness in self.index.values():
            self.assertTrue(witness["original_upstream_test_passed"])
            self.assertTrue(witness["original_source_with_fixed_security_regression_failed_expected_assertion"])
            self.assertTrue(witness["fixed_source_with_same_regression_passed"])
            self.assertFalse(witness["independent_human_gold"])
            self.assertTrue(witness["run_url"].startswith("https://github.com/Iniwura/falsum/actions/runs/"))

    def test_all_four_real_fixed_source_witnesses_support_true_and_contradict_false(self):
        for key,witness in self.index.items():
            with self.subTest(key=key):
                true=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
                false=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_FAILS")
                a=g.evaluate(self.index,true)
                b=g.evaluate(self.index,false)
                self.assertEqual(a["verdict"],"SUPPORTED")
                self.assertEqual(a["source_revision"],"fixed")
                self.assertEqual(b["verdict"],"CONTRADICTED")
                self.assertFalse(a["trained_model_accuracy_measurement"])
                self.assertTrue(a["not_independent_appsec_gold"])

    def test_all_four_vulnerable_parent_witnesses_support_failure_contradict_pass(self):
        for key,witness in self.index.items():
            with self.subTest(key=key):
                true=g.canonical_claim(witness,"parent","UPSTREAM_REGRESSION_FAILS")
                false=g.canonical_claim(witness,"parent","UPSTREAM_REGRESSION_PASSES")
                self.assertEqual(g.evaluate(self.index,true)["verdict"],"SUPPORTED")
                self.assertEqual(g.evaluate(self.index,false)["verdict"],"CONTRADICTED")

    def test_no_unsupported_production_exploit_or_universal_safety_promoted(self):
        for key,witness in self.index.items():
            for revision in ("parent","fixed"):
                for claim in ("CONFIRMED_PRODUCTION_EXPLOIT",
                              "GUARANTEED_UNIVERSAL_APPLICATION_SAFETY"):
                    with self.subTest(key=key,rev=revision,claim=claim):
                        result=g.evaluate(self.index,g.canonical_claim(witness,revision,claim))
                        self.assertEqual(result["verdict"],"ABSTAIN")
                        self.assertEqual(result["reason"],"DEPLOYED_IMPACT_OR_GLOBAL_SECURITY_NOT_TESTED")
                        self.assertFalse(result["production_exploitability_assessed"])

    def test_unknown_commit_source_blob_or_receipt_sha_cannot_be_accepted(self):
        for key,witness in self.index.items():
            clean=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
            variants=[
                ("unverified_git_sha",lambda d:d.update(upstream_commit="0"*40)),
                ("wrong_source_sha",lambda d:d["evidence"].update(source_blob_sha1="0"*40)),
                ("wrong_test_sha",lambda d:d["evidence"].update(
                    new_security_regression_test_blob_sha1="0"*40)),
                ("forged_log_sha",lambda d:d["evidence"].update(
                    actual_execution_receipt_sha256="0"*64)),
                ("unknown_assertion",lambda d:d.update(claim_type="CLAIM_ABOUT_UNTESTED_PRODUCTION")),
            ]
            for name,mutate in variants:
                doc=copy.deepcopy(clean);mutate(doc)
                with self.subTest(key=key,mutation=name):
                    report=g.evaluate(self.index,doc)
                    self.assertEqual(report["verdict"],"ABSTAIN")
                    self.assertNotEqual(report["reason"],"REAL_PARENT_FAILS_FIXED_PASSES_TEST_WITNESS")

    def test_source_summary_cannot_be_relabelled_as_expert_certified_or_network_ready(self):
        original=json.loads(INDEX_RAW)
        for mutate in (
            lambda d:d["assertions"].update(independent_expert_gold_labels=1),
            lambda d:d["assertions"].update(trained_model_improvement_proven=True),
            lambda d:d["assertions"].update(registered_evaluator=True),
            lambda d:d["assertions"].update(official_h2_submitted=True),
            lambda d:d["counts"].update(real_execution_original_pass_new_parent_test_fail_fixed_test_pass=8),
            lambda d:d["source_run"].update(original_unmodified_extracted_json_sha256="0"*64),
            lambda d:d["receipts"][0].update(original_source_git_blob="0"*40),
            lambda d:d["receipts"][1].update(same_fixed_upstream_regression_test_git_blob="0"*40),
        ):
            d=copy.deepcopy(original);mutate(d)
            with self.assertRaises(g.SourceWitnessError):
                g.validated_index(json.dumps(d).encode(),SOURCE_RAW)

    def test_synthetic_32_control_cases_are_explicitly_not_model_accuracy(self):
        report=g.run(INDEX_RAW,SOURCE_RAW)
        self.assertEqual(report["claims_evaluated"],32)
        self.assertEqual(report["constructed_fixtures_checked"],32)
        self.assertEqual(report["constructed_fixture_matches"],32)
        self.assertEqual(report["supported"],8)
        self.assertEqual(report["contradicted"],8)
        self.assertEqual(report["abstained"],16)
        self.assertTrue(report["not_a_semantic_or_neural_security_evaluator"])
        self.assertTrue(report["not_a_telegraph_network_adapter"])
        self.assertTrue(report["not_an_independent_human_gold_benchmark"])
        self.assertFalse(report["trained_model_improvement_proven"])
        self.assertEqual(report["independent_appsec_expert_labels"],0)
        self.assertEqual(report["new_anjo_network_evaluation_rows"],0)
        self.assertFalse(report["official_hackathon_submission_confirmed"])

    def test_custom_claims_do_not_leak_prompts_or_return_source_text(self):
        witness=self.index["hono-csrf"]
        valid=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
        report=g.run(INDEX_RAW,SOURCE_RAW,examples=[{
            "test_id":"case-A","claim":valid,
        }])
        self.assertEqual(report["supported"],1)
        self.assertEqual(report["constructed_fixtures_checked"],0)
        self.assertEqual(report["constructed_fixture_matches"],0)
        self.assertNotIn("prompt",json.dumps(report).lower())
        self.assertNotIn("vulnerable private user",json.dumps(report).lower())

    def test_external_caller_supplied_correct_label_does_not_count_as_constructed_proof(self):
        witness=self.index["koa-redirect"]
        c=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
        report=g.run(INDEX_RAW,SOURCE_RAW,examples=[{
            "test_id":"caller-chose-passing-label",
            "claim":c,"expected":"SUPPORTED",
        }])
        self.assertEqual(report["supported"],1)
        self.assertEqual(report["constructed_fixtures_checked"],0)
        self.assertEqual(report["constructed_fixture_matches"],0)
        self.assertEqual(report["external_caller_expectations_seen"],1)
        self.assertEqual(report["expectation_provenance"],
                         "EXTERNAL_INPUT_UNVERIFIED_CALLER_EXPECTATIONS")
        row=report["cases"][0]
        self.assertEqual(row["unverified_caller_expected_verdict"],"SUPPORTED")
        self.assertTrue(row["matches_unverified_caller_expectation"])
        self.assertNotIn("constructed_expectation",row)
        self.assertNotIn("matches_source_derived_expectation",row)
        self.assertFalse(report["trained_model_improvement_proven"])

    def test_external_caller_supplied_incorrect_label_is_not_treated_as_gold(self):
        witness=self.index["hono-csrf"]
        c=g.canonical_claim(witness,"parent","UPSTREAM_REGRESSION_FAILS")
        report=g.run(INDEX_RAW,SOURCE_RAW,examples=[{
            "test_id":"caller-chose-incorrect-label",
            "claim":c,"expected":"CONTRADICTED",
        }])
        self.assertEqual(report["supported"],1)
        self.assertEqual(report["external_caller_expectations_seen"],1)
        self.assertFalse(report["cases"][0]["matches_unverified_caller_expectation"])
        self.assertEqual(report["constructed_fixture_matches"],0)
        self.assertEqual(report["constructed_fixtures_checked"],0)
        self.assertEqual(report["independent_appsec_expert_labels"],0)
        self.assertEqual(report["cases"][0]["judgement"]["verdict"],"SUPPORTED")

    def test_internal_source_derived_suite_keeps_independent_provenance_marker(self):
        report=g.run(INDEX_RAW,SOURCE_RAW)
        self.assertEqual(report["expectation_provenance"],
                         "INTERNAL_SOURCE_DERIVED_REGRESSION_FIXTURES")
        self.assertEqual(report["external_caller_expectations_seen"],0)
        self.assertEqual(report["constructed_fixtures_checked"],32)
        self.assertEqual(report["constructed_fixture_matches"],32)
        self.assertNotIn("unverified_caller_expected_verdict",report["cases"][0])

    def test_malformed_extra_request_fields_or_repeated_test_id_fails_closed(self):
        witness=self.index["koa-redirect"]
        valid=g.canonical_claim(witness,"fixed","UPSTREAM_REGRESSION_PASSES")
        with self.assertRaises(g.SourceWitnessError):
            g.evaluate(self.index,dict(valid,secret="PRIVATE HIDDEN ANSWER"))
        with self.assertRaises(g.SourceWitnessError):
            g.run(INDEX_RAW,SOURCE_RAW,examples=[
                {"test_id":"duplicate","claim":valid},
                {"test_id":"duplicate","claim":valid},
            ])
        with self.assertRaises(g.SourceWitnessError):
            g.run(INDEX_RAW,SOURCE_RAW,examples=[
                {"test_id":"fake","claim":valid,"expected":"MODEL_RANKS_HIGH"},
            ])

    def test_unknown_source_case_fail_closed_to_abstain(self):
        a=g.canonical_claim(self.index["koa-redirect"],"fixed","UPSTREAM_REGRESSION_PASSES")
        a["case_id"]="unverified-project"
        r=g.evaluate(self.index,a)
        self.assertEqual(r["verdict"],"ABSTAIN")
        self.assertEqual(r["reason"],"SOURCE_OR_ASSERTION_NOT_VERIFIED")

    def test_source_lock_unauthenticated_or_wrong_bytes_rejected(self):
        with self.assertRaises(g.SourceWitnessError):
            g.validated_index(INDEX_RAW,b'{"no_source_lock":true}')
        with self.assertRaises(g.SourceWitnessError):
            g.validated_index(b"UNPARSABLE JSON",SOURCE_RAW)

    def test_cli_does_not_overwrite_or_use_hidden_private_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            out=root/"generated-public-source-gate.json"
            self.assertEqual(g.main([
                "--index",str(INDEX_PATH),"--source-lock",str(SOURCE_PATH),
                "--out",str(out),
            ]),0)
            result=json.loads(out.read_text())
            self.assertEqual(result["constructed_fixture_matches"],32)
            self.assertEqual(result["independent_appsec_expert_labels"],0)
            with self.assertRaises(SystemExit):
                g.main(["--index",str(INDEX_PATH),"--source-lock",str(SOURCE_PATH),
                        "--out",str(out)])
            with self.assertRaises(SystemExit):
                g.main(["--index",str(INDEX_PATH),"--source-lock",str(SOURCE_PATH),
                        "--out",str(INDEX_PATH)])

if __name__=="__main__":
    unittest.main()
