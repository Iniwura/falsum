"""Adversarial source-bound prediction benchmark tests.

Synthetic evaluator guesses in these tests are NOT independently scored human
AppSec reviews or genuine third-party model accuracy observations.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5f_evaluator_scorecard as s
from falsum import source_review_witness_gate as original

ROOT = Path(__file__).resolve().parents[1]


class OpenBookSecurityReviewEvaluatorScorecardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge,cls.answers,cls.source = s.construct(ROOT)

    def test_no_answer_labels_in_exported_questions_and_all_sources_are_pinned(self):
        doc=self.challenge
        self.assertEqual(doc["status"],s.CHALLENGE_STATUS)
        self.assertEqual(len(doc["questions"]),80)
        self.assertFalse(doc["answer_labels_in_challenge"])
        self.assertFalse(doc["blind_holdout"])
        self.assertEqual(doc["independent_expert_gold_labels"],0)
        self.assertEqual(doc["source_fix_stages"],5)
        self.assertEqual(doc["upstream_projects"],4)
        self.assertTrue(all(row["source_url"].startswith("https://github.com/")
                            and row["upstream_regression_test_url"].startswith("https://github.com/")
                            and row["original_real_execution_run_url"].startswith("https://github.com/")
                            for row in doc["questions"]))
        self.assertFalse(any("expected" in row or "correct_verdict" in row
                             for row in doc["questions"]))
        self.assertEqual(s.digest(s.canonical(self.source)),
                         doc["reference_source_report_sha256"])

    def test_author_constructed_ground_truth_has_80_checks_with_class_imbalance(self):
        self.assertEqual(len(self.answers),80)
        self.assertEqual({v:list(self.answers.values()).count(v) for v in original.RESULTS},
                         {"SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":60})
        self.assertEqual(len(set(self.answers)),3)

    def test_always_abstain_looks_75_percent_accurate_but_macro_recall_is_one_third(self):
        preds=s.baseline_predictions(self.challenge,"always-abstain")
        report=s.score(self.challenge,self.answers,preds,origin="SYNTHETIC_CONSTANT_BASELINE")
        self.assertEqual(report["exact_matches"],60)
        self.assertEqual(report["raw_exact_match_ratio"],0.75)
        self.assertAlmostEqual(report["macro_class_recall"],1/3,places=6)
        self.assertEqual(report["fully_correct_parent_fix_reversals"],0)
        self.assertEqual(report["supported_or_contradicted_facts_abstained_on"],20)
        self.assertEqual(report["unsupported_confident_claims"],0)
        self.assertEqual(report["independently_certified_human_appsec_gold_labels"],0)
        self.assertFalse(report["trained_model_performance_improvement_claimed"])

    def test_always_supported_or_contradicted_do_not_claim_valid_source_reversals(self):
        for strategy in ("always-supported","always-contradicted"):
            with self.subTest(strategy=strategy):
                report=s.score(self.challenge,self.answers,
                               s.baseline_predictions(self.challenge,strategy),
                               origin="SYNTHETIC_CONSTANT_BASELINE")
                self.assertEqual(report["raw_exact_match_ratio"],0.125)
                self.assertAlmostEqual(report["macro_class_recall"],1/3,places=6)
                self.assertEqual(report["unsupported_confident_claims"],60)
                self.assertEqual(report["fully_correct_parent_fix_reversals"],0)

    def test_ideal_synthetic_fixture_can_only_prove_internal_scoring_consistency(self):
        result=s.score(self.challenge,self.answers,self.answers,
                       origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(result["exact_matches"],80)
        self.assertEqual(result["macro_class_recall"],1)
        self.assertEqual(result["fully_correct_parent_fix_reversals"],5)
        self.assertEqual(result["unsupported_confident_claims"],0)
        self.assertEqual(result["supported_or_contradicted_facts_abstained_on"],0)
        self.assertEqual(result["independently_certified_human_appsec_gold_labels"],0)
        self.assertFalse(result["trained_model_performance_improvement_claimed"])
        self.assertFalse(result["network_evaluator_registered"])
        self.assertEqual(result["prediction_provenance"],"EXTERNAL_UNVERIFIED_PREDICTIONS")

    def test_one_unsupported_confident_claim_and_one_revision_miss_are_observed(self):
        guesses=dict(self.answers)
        unsupported=next(k for k,v in guesses.items() if v=="ABSTAIN")
        source_fact=next(k for k,v in guesses.items() if v=="SUPPORTED"
                         and k.endswith("|original"))
        guesses[unsupported]="SUPPORTED"
        guesses[source_fact]="CONTRADICTED"
        report=s.score(self.challenge,self.answers,guesses,origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(report["exact_matches"],78)
        self.assertEqual(report["unsupported_confident_claims"],1)
        self.assertEqual(report["fully_correct_parent_fix_reversals"],4)
        self.assertEqual(report["confusion_matrix_true_rows_predicted_columns"]["ABSTAIN"]["SUPPORTED"],1)
        self.assertEqual(report["confusion_matrix_true_rows_predicted_columns"]["SUPPORTED"]["CONTRADICTED"],1)

    def test_external_prediction_template_is_deliberately_unscorable_until_filled(self):
        template=s.prediction_template(self.challenge)
        self.assertEqual(template["challenge_sha256"],s.digest(s.canonical(self.challenge)))
        self.assertTrue(all(p["verdict"] is None for p in template["predictions"]))
        with self.assertRaises(s.ScorecardError):
            s.validate_predictions(self.challenge,template)
        filled=copy.deepcopy(template)
        for row in filled["predictions"]:
            row["verdict"]=self.answers[row["id"]]
        parsed=s.validate_predictions(self.challenge,filled)
        self.assertEqual(parsed,self.answers)
        self.assertEqual(len(parsed),80)

    def test_forged_wrong_challenge_sha_duplicate_prediction_and_wrong_order_fail_closed(self):
        valid=s.prediction_template(self.challenge)
        for row in valid["predictions"]:
            row["verdict"]="ABSTAIN"
        changes=[
            lambda x:x.update(challenge_sha256="0"*64),
            lambda x:x["predictions"].pop(),
            lambda x:x["predictions"].append(copy.deepcopy(x["predictions"][0])),
            lambda x:x["predictions"].reverse(),
            lambda x:x["predictions"][0].update(verdict="CERTIFIED_GOLD"),
            lambda x:x["predictions"][0].update(secret_answer="STEAL"),
            lambda x:x.update(human_expert_gold_labels=80),
            lambda x:x.update(status="REVIEWED_BY_SECURITY_EXPERTS"),
            lambda x:x.update(schema_version=True),
        ]
        for change in changes:
            with self.subTest(change=str(change)):
                fixture=copy.deepcopy(valid)
                change(fixture)
                with self.assertRaises(s.ScorecardError):
                    s.validate_predictions(self.challenge,fixture)

    def test_duplicate_json_object_key_and_overlong_private_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"bad.json"
            p.write_text('{"status":"A","status":"B"}',encoding="utf-8")
            with self.assertRaises(s.ScorecardError):
                s.read_predictions(p)
            p.write_text("x"*81000,encoding="utf-8")
            with self.assertRaises(s.ScorecardError):
                s.read_predictions(p)

    def test_cli_exports_no_answer_key_scores_constant_baselines_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            challenge=base/"challenge.json"
            blank=base/"template.json"
            self.assertEqual(s.main(["--root",str(ROOT),"export","--challenge-out",
                                     str(challenge),"--template-out",str(blank)]),0)
            self.assertEqual(len(json.loads(challenge.read_text())["questions"]),80)
            self.assertTrue(all(x["verdict"] is None for x in json.loads(blank.read_text())["predictions"]))
            with self.assertRaises(SystemExit):
                s.main(["--root",str(ROOT),"export","--challenge-out",
                        str(challenge),"--template-out",str(blank)])
            baseline=base/"always-abstain.json"
            self.assertEqual(s.main(["--root",str(ROOT),"baseline","--strategy",
                                     "always-abstain","--out",str(baseline)]),0)
            report=json.loads(baseline.read_text())
            self.assertEqual(report["baseline_strategy"],"always-abstain")
            self.assertEqual(report["raw_exact_match_ratio"],0.75)
            self.assertEqual(report["macro_class_recall"],0.333333)
            self.assertEqual(report["prediction_provenance"],"SYNTHETIC_CONSTANT_BASELINE")
            with self.assertRaises(SystemExit):
                s.main(["--root",str(ROOT),"baseline","--strategy",
                        "always-abstain","--out",str(baseline)])

    def test_cli_scores_declared_predictions_without_upgrading_them_to_gold(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)
            inp=base/"predictions.json"
            out=base/"score.json"
            template=s.prediction_template(self.challenge)
            for row in template["predictions"]:
                row["verdict"]="ABSTAIN"
            inp.write_text(json.dumps(template),encoding="utf-8")
            self.assertEqual(s.main(["--root",str(ROOT),"score","--predictions",
                                     str(inp),"--out",str(out)]),0)
            report=json.loads(out.read_text())
            self.assertEqual(report["exact_matches"],60)
            self.assertEqual(report["prediction_provenance"],"EXTERNAL_UNVERIFIED_PREDICTIONS")
            self.assertEqual(report["independently_certified_human_appsec_gold_labels"],0)
            with self.assertRaises(SystemExit):
                s.main(["--root",str(ROOT),"score","--predictions",
                        str(inp),"--out",str(inp)])

    def test_modified_source_proof_and_missing_zip_cannot_construct_real_benchmark(self):
        from unittest.mock import patch
        with patch.object(s.source,"assemble",side_effect=ValueError("source digest tampered")):
            with self.assertRaises(ValueError):
                s.construct(ROOT)
        modified=copy.deepcopy(self.source)
        modified["independent_appsec_expert_gold_labels"]=1
        with patch.object(s.source,"assemble",return_value=modified):
            with self.assertRaises(s.ScorecardError):
                s.construct(ROOT)

    def test_score_cannot_accept_missing_ids_or_undocumented_origin(self):
        guesses=s.baseline_predictions(self.challenge,"always-abstain")
        del guesses[next(iter(guesses))]
        with self.assertRaises(s.ScorecardError):
            s.score(self.challenge,self.answers,guesses,
                    origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        with self.assertRaises(s.ScorecardError):
            s.score(self.challenge,self.answers,
                    s.baseline_predictions(self.challenge,"always-abstain"),
                    origin="INDEPENDENT_CERTIFIED_HUMAN_GOLD")


if __name__=="__main__":
    unittest.main()
