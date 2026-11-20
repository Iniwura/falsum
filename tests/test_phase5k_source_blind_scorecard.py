"""Adversarial benchmark leak tests. Synthetic metadata attacker is NOT a model."""
from __future__ import annotations

from collections import Counter
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase5k_source_blind_scorecard as v2
from falsum import phase5f_evaluator_scorecard as v1


class PublicSourceChallengeFalsificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge, cls.answers, cls.mapping = v2.build()
        cls.old_challenge, cls.old_answers, cls.source_proof = v1.construct()

    def test_legacy_source_blind_rule_reconstructs_all_80_without_git_or_model(self):
        report=v2.legacy_leak_audit()
        self.assertEqual(report["status"],v2.AUDIT_STATUS)
        self.assertEqual(report["source_blind_predictions_matching"],80)
        self.assertEqual(report["source_blind_raw_match"],1)
        self.assertEqual(report["source_blind_macro_class_recall"],1)
        self.assertEqual(report["source_blind_full_parent_fix_reversals"],5)
        self.assertFalse(report["source_code_or_regression_test_read"])
        self.assertFalse(report["model_inference_used"])
        self.assertEqual(report["legacy_scorecard_as_model_accuracy"],"INVALID")
        self.assertEqual(report["independent_human_gold"],0)
        self.assertEqual(len(report["answer_bearing_public_metadata"]),3)

    def test_public_v2_has_30_balanced_no_answer_questions_and_original_ci_source(self):
        c=self.challenge
        self.assertEqual(c["status"],v2.QUESTION_STATUS)
        self.assertEqual(c["question_count"],30)
        self.assertEqual(Counter(self.answers.values()),{
            "SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":10,
        })
        self.assertEqual(c["historical_test_stages"],5)
        self.assertEqual(c["distinct_projects"],4)
        self.assertFalse(c["answer_labels_exported"])
        self.assertTrue(c["not_source_or_model_blind"])
        self.assertEqual(c["independent_human_appsec_gold"],0)
        self.assertEqual(c["reference_source_evidence_sha256"],
                         v1.digest(v1.canonical(self.source_proof)))
        ids=[q["id"] for q in c["questions"]]
        self.assertEqual(len(set(ids)),30)
        self.assertTrue(all(len(k)==32 and all(c in "0123456789abcdef" for c in k)
                            for k in ids))
        for q in c["questions"]:
            self.assertFalse(set(q)&{
                "revision","receipt_integrity","expected","answer","label",
                "parent_or_fixed","v1_id",
            })
            self.assertIn(q["source_slot"],("A","B"))
            self.assertTrue(q["source_code_url"].startswith("https://github.com/"))
            self.assertTrue(q["actual_original_test_ci_url"].startswith("https://github.com/"))
            self.assertEqual(len(q["source_git_commit"]),40)
            self.assertEqual(len(q["submitted_execution_receipt_sha256"]),64)

    def test_neutral_slots_are_not_a_global_parent_fixed_role(self):
        per_case={}
        for q in self.challenge["questions"]:
            m=self.mapping[q["id"]]
            case=q["historical_source_case"]
            per_case.setdefault(case, {})[m["revision"]]=q["source_slot"]
        self.assertEqual(len(per_case),5)
        self.assertEqual(Counter(x["parent"] for x in per_case.values()),{
            "A":3,"B":2,
        })
        self.assertTrue(all(set(x.values())=={"A","B"} for x in per_case.values()))
        self.assertEqual(set(m["v1_id"] for m in self.mapping.values()) &
                         set(self.old_answers),set(m["v1_id"] for m in self.mapping.values()))

    def test_disclosed_source_blind_slot_guess_no_longer_gets_perfect_score(self):
        guesses=v2.baseline(self.challenge,"slot-a-is-parent")
        report=v2.evaluate(self.challenge,self.answers,self.mapping,guesses,
                           origin="SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE")
        self.assertEqual(report["exact_matches"],22)
        self.assertEqual(report["raw_match_ratio"],0.733333)
        self.assertEqual(report["macro_class_recall"],0.733333)
        self.assertEqual(report["complete_source_sensitive_parent_fix_reversals"],3)
        self.assertEqual(report["reference_class_distribution"],
                         {"SUPPORTED":10,"CONTRADICTED":10,"ABSTAIN":10})
        self.assertTrue(report["not_an_independent_blind_security_review_accuracy_measurement"])
        self.assertEqual(report["independent_human_gold_labels"],0)
        self.assertFalse(report["actual_trained_model_comparison"])

    def test_constant_abstain_and_constant_confident_guesses_at_one_third(self):
        for strategy in ("always-abstain","always-supported","always-contradicted"):
            with self.subTest(strategy=strategy):
                guess=v2.baseline(self.challenge,strategy)
                report=v2.evaluate(self.challenge,self.answers,self.mapping,guess,
                                   origin="SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE")
                self.assertEqual(report["exact_matches"],10)
                self.assertEqual(report["raw_match_ratio"],0.333333)
                self.assertEqual(report["macro_class_recall"],0.333333)
                self.assertEqual(report["complete_source_sensitive_parent_fix_reversals"],0)
                self.assertEqual(report["independent_human_gold_labels"],0)
                self.assertFalse(report["registered_telegraph_evaluator"])

    def test_perfect_author_reference_fixture_not_promoted_into_model_gold(self):
        result=v2.evaluate(self.challenge,self.answers,self.mapping,self.answers,
                           origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(result["exact_matches"],30)
        self.assertEqual(result["complete_source_sensitive_parent_fix_reversals"],5)
        self.assertEqual(result["macro_class_recall"],1)
        self.assertEqual(result["independent_human_gold_labels"],0)
        self.assertFalse(result["actual_trained_model_comparison"])
        self.assertEqual(result["candidate_origin"],"EXTERNAL_UNVERIFIED_PREDICTIONS")

    def test_one_false_source_fact_and_one_false_production_claim_count_both_errors(self):
        fake=dict(self.answers)
        fact=next(k for k,v in fake.items() if v=="SUPPORTED")
        unknown=next(k for k,v in fake.items() if v=="ABSTAIN")
        fake[fact]="ABSTAIN"
        fake[unknown]="SUPPORTED"
        result=v2.evaluate(self.challenge,self.answers,self.mapping,fake,
                           origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(result["exact_matches"],28)
        self.assertEqual(result["unsupported_confident_verdicts"],1)
        self.assertEqual(result["known_source_facts_missed_by_abstaining"],1)
        self.assertEqual(result["complete_source_sensitive_parent_fix_reversals"],4)

    def test_external_template_unfilled_cannot_score_until_true_predicted(self):
        input_doc=v2.template(self.challenge)
        self.assertEqual(input_doc["challenge_sha256"],
                         v2.digest(v2.canonical(self.challenge)))
        self.assertTrue(all(q["verdict"] is None for q in input_doc["predictions"]))
        with self.assertRaises(v2.SourceShortcutError):
            v2.validate(self.challenge,input_doc)
        for q in input_doc["predictions"]:
            q["verdict"]="ABSTAIN"
        self.assertEqual(len(v2.validate(self.challenge,input_doc)),30)

    def test_forged_prediction_keys_gold_labels_order_or_sha_fail_closed(self):
        valid=v2.template(self.challenge)
        for q in valid["predictions"]:
            q["verdict"]="ABSTAIN"
        mutations=[
            lambda d:d.update(challenge_sha256="0"*64),
            lambda d:d.update(status="INDEPENDENT_SECURITY_GOLD"),
            lambda d:d.update(schema_version=True),
            lambda d:d.update(independent_expert_labels=30),
            lambda d:d["predictions"].pop(),
            lambda d:d["predictions"].append(copy.deepcopy(d["predictions"][0])),
            lambda d:d["predictions"].reverse(),
            lambda d:d["predictions"][0].update(verdict="CERTIFIED_SOURCE_SAFE"),
            lambda d:d["predictions"][0].update(gold_label="SUPPORTED"),
            lambda d:d["predictions"][0].update(id="unknown"),
        ]
        for change in mutations:
            with self.subTest(change=str(change)):
                candidate=copy.deepcopy(valid)
                change(candidate)
                with self.assertRaises(v2.SourceShortcutError):
                    v2.validate(self.challenge,candidate)

    def test_alternate_origin_cannot_claim_external_human_approval(self):
        with self.assertRaises(v2.SourceShortcutError):
            v2.evaluate(self.challenge,self.answers,self.mapping,self.answers,
                        origin="HUMAN_EXPERT_CERTIFIED_GOLD")

    def test_source_provenance_changed_fails_instead_of_fabricating_score(self):
        with patch.object(v2.legacy,"construct",side_effect=ValueError("source ZIP tampered")):
            with self.assertRaises(ValueError):
                v2.build()
        fake=dict(self.old_answers)
        fake[next(iter(fake))]="NOT_A_RESULT"
        with patch.object(v2.legacy,"construct",return_value=(
                self.old_challenge,fake,self.source_proof)):
            with self.assertRaises(v2.SourceShortcutError):
                v2.build()

    def test_report_catches_both_legacy_perfect_shortcut_and_balanced_v2_limits(self):
        r=v2.report()
        self.assertEqual(r["legacy"]["source_blind_predictions_matching"],80)
        self.assertEqual(r["balanced_v2"]["questions"],30)
        self.assertEqual(r["balanced_v2"]["source_blind_slot_baseline"]["exact_matches"],22)
        self.assertEqual(r["balanced_v2"]["always_abstain_baseline"]["exact_matches"],10)
        self.assertFalse(r["first_place_claim_proven"])

    def test_cli_export_audit_and_baseline_no_credentials_no_answers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            audit=root/"audit.json"
            challenge=root/"challenge.json"
            template=root/"template.json"
            baseline=root/"baseline.json"
            self.assertEqual(v2.main(["audit","--out",str(audit)]),0)
            self.assertEqual(json.loads(audit.read_text())["legacy"]["source_blind_predictions_matching"],80)
            self.assertEqual(v2.main(["export","--questions-out",str(challenge),
                                      "--template-out",str(template)]),0)
            public=json.loads(challenge.read_text())
            self.assertEqual(len(public["questions"]),30)
            self.assertTrue(all(row["verdict"] is None for row in
                                json.loads(template.read_text())["predictions"]))
            self.assertEqual(v2.main(["baseline","--strategy","slot-a-is-parent",
                                      "--out",str(baseline)]),0)
            self.assertEqual(json.loads(baseline.read_text())["exact_matches"],22)
            with self.assertRaises(SystemExit):
                v2.main(["audit","--out",str(audit)])
            with self.assertRaises(SystemExit):
                v2.main(["export","--questions-out",str(challenge),
                         "--template-out",str(template)])

    def test_cli_will_score_actual_complete_caller_predictions_without_gold_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            incoming=root/"predictions.json"
            result=root/"result.json"
            guesses=v2.template(self.challenge)
            for row in guesses["predictions"]:
                row["verdict"]="ABSTAIN"
            incoming.write_text(json.dumps(guesses))
            self.assertEqual(v2.main(["score","--predictions",str(incoming),
                                      "--out",str(result)]),0)
            doc=json.loads(result.read_text())
            self.assertEqual(doc["candidate_origin"],"EXTERNAL_UNVERIFIED_PREDICTIONS")
            self.assertEqual(doc["exact_matches"],10)
            self.assertEqual(doc["independent_human_gold_labels"],0)
            with self.assertRaises(SystemExit):
                v2.main(["score","--predictions",str(incoming),"--out",str(incoming)])

    def test_installed_falsum_cli_audit_and_export(self):
        from falsum.cli import main as app
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            audit=root/"audit.json"
            questions=root/"questions.json"
            template=root/"template.json"
            self.assertEqual(app(["score-source-balanced","audit","--out",str(audit)]),0)
            self.assertEqual(app(["score-source-balanced","export",
                                  "--questions-out",str(questions),
                                  "--template-out",str(template)]),0)
            self.assertEqual(json.loads(questions.read_text())["question_count"],30)
            self.assertEqual(json.loads(audit.read_text())["legacy"]["source_blind_predictions_matching"],80)


if __name__=="__main__":
    unittest.main()
