"""Adversarial tests for public three-choice candidate scoring, not real model runs."""
from __future__ import annotations

from collections import Counter
import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5m_source_context_candidate as c


class PublicCodeSensitiveCandidateScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.challenge,cls.truth,cls.mapping=c.construct()

    def test_exact_historical_source_origin_and_no_gold_promotion(self):
        challenge=self.challenge
        self.assertEqual(challenge["status"],c.STATUS_CHALLENGE)
        self.assertEqual(challenge["public_questions"],3)
        self.assertEqual(challenge["distinct_upstream_projects"],1)
        self.assertEqual(challenge["source_revision_conditions"],2)
        self.assertEqual(challenge["source_omitted_controls"],1)
        self.assertTrue(challenge["answer_key_excluded"])
        self.assertTrue(challenge["not_model_or_pretraining_blind"])
        self.assertFalse(challenge["actual_model_scores_included"])
        self.assertEqual(challenge["independent_appsec_expert_gold_labels"],0)
        self.assertEqual(challenge["source_replay_evidence_run"],
                         "https://github.com/Iniwura/falsum/actions/runs/44716279199")
        self.assertEqual(Counter(self.truth.values()),{
            "A":1,"B":1,"ABSTAIN":1
        })

    def test_public_questions_have_exact_github_source_links_no_explicit_answer_or_role(self):
        q=self.challenge["questions"]
        self.assertEqual(len(q),3)
        self.assertEqual(len({x["id"] for x in q}),3)
        self.assertEqual([x["id"] for x in q],sorted(x["id"] for x in q))
        for question in q:
            self.assertEqual(set(question),{
                "id","question","answer_options","response_choices",
                "source_git_sha","source_code_url",
            })
            self.assertEqual(len(question["id"]),32)
            self.assertTrue(all(z in "0123456789abcdef" for z in question["id"]))
            self.assertEqual([a["choice"] for a in question["answer_options"]],["A","B"])
            self.assertEqual(question["response_choices"],["A","B","ABSTAIN"])
            self.assertNotIn("parent",question["question"].lower())
            self.assertNotIn("fixed",question["question"].lower())
            self.assertNotIn("expected",question)
            if question["source_git_sha"] is not None:
                self.assertEqual(len(question["source_git_sha"]),40)
                self.assertIn(question["source_git_sha"],question["source_code_url"])
            else:
                self.assertIsNone(question["source_code_url"])
                self.assertIn("source is deliberately unavailable",question["question"])

    def test_null_template_is_unscorable_even_if_same_challenge(self):
        blank=c.template(self.challenge)
        self.assertEqual(blank["challenge_sha256"],c.sha(c.canonical_json(self.challenge)))
        self.assertTrue(all(row["choice"] is None for row in blank["decisions"]))
        with self.assertRaises(c.DiagnosticError):
            c.validate(self.challenge,blank)

    def test_exact_three_source_facts_score_only_constructed_reference(self):
        blank=c.template(self.challenge)
        for row in blank["decisions"]:
            row["choice"]=self.truth[row["id"]]
            row["reason"]="My separate reviewer examined the public source condition."
        submitted=c.validate(self.challenge,blank)
        results=c.score(self.challenge,self.truth,self.mapping,submitted,
                        origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(results["total_exact_source_derived_matches"],3)
        self.assertEqual(results["source_fact_matches_out_of_two"],2)
        self.assertTrue(results["source_sensitive_complete_correct_reversal"])
        self.assertTrue(results["no_source_control_abstained"])
        self.assertTrue(results["source_context_choice_changed"])
        self.assertFalse(results["statistically_valid_model_accuracy_estimate"])
        self.assertFalse(results["model_inference_performed_by_this_scorer"])
        self.assertEqual(results["independent_human_expert_gold_labels"],0)

    def test_all_disclosed_constant_baselines_do_not_fake_source_reversal(self):
        for strategy in c.BASELINES:
            with self.subTest(strategy=strategy):
                b=c.baseline(self.challenge,strategy)
                s=c.score(self.challenge,self.truth,self.mapping,b,
                          origin="SYNTHETIC_DISCLOSED_BASELINE")
                self.assertEqual(s["total_exact_source_derived_matches"],1)
                self.assertEqual(s["raw_match_fraction"],0.333333)
                self.assertEqual(s["macro_class_recall"],0.333333)
                self.assertFalse(s["source_sensitive_complete_correct_reversal"])
                self.assertFalse(s["source_context_choice_changed"])
                self.assertFalse(s["registered_telegraph_evaluator"])

    def test_confident_guess_without_source_does_not_count_as_correct(self):
        predictions={ident:("A" if role=="source-omitted" else self.truth[ident])
                     for ident,role in self.mapping.items()}
        s=c.score(self.challenge,self.truth,self.mapping,predictions,
                  origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
        self.assertEqual(s["source_fact_matches_out_of_two"],2)
        self.assertEqual(s["total_exact_source_derived_matches"],2)
        self.assertFalse(s["no_source_control_abstained"])
        self.assertFalse(s["statistically_valid_model_accuracy_estimate"])

    def test_forged_evaluator_gold_extra_keys_or_bad_order_fail(self):
        blank=c.template(self.challenge)
        for row in blank["decisions"]:
            row["choice"]="ABSTAIN"
        corrupt=[
            lambda v:v.update(challenge_sha256="f"*64),
            lambda v:v.update(status="INDEPENDENT_GOLD_3_OF_3"),
            lambda v:v.update(schema_version=True),
            lambda v:v.update(reviewer_verified=True),
            lambda v:v["decisions"].pop(),
            lambda v:v["decisions"].reverse(),
            lambda v:v["decisions"][0].update(choice="EXPERT_PROVEN"),
            lambda v:v["decisions"][0].update(id="guess"),
            lambda v:v["decisions"][0].update(expert_label="SUPPORTED"),
            lambda v:v["decisions"][0].update(reason=12345),
            lambda v:v["decisions"][0].update(reason="x"*1201),
        ]
        for f in corrupt:
            with self.subTest(change=str(f)):
                x=copy.deepcopy(blank)
                f(x)
                with self.assertRaises(c.DiagnosticError):
                    c.validate(self.challenge,x)

    def test_candidate_cannot_claim_expert_verified_prediction_origin(self):
        with self.assertRaises(c.DiagnosticError):
            c.score(self.challenge,self.truth,self.mapping,self.truth,
                    origin="INDEPENDENT_QUALIFIED_APPSEC_GOLD")

    def test_cannot_write_or_overwrite_gold_json_from_candidate_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            target=root/"candidate.json"
            c.write_new(target,{"name":"not original source evidence"})
            with self.assertRaises(c.DiagnosticError):
                c.write_new(target,{"model_gold":True})

    def test_installed_cli_export_blank_then_baseline_then_score_real_caller_decisions(self):
        from falsum.cli import main as cli
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            questions=root/"questions.json"
            template=root/"template.json"
            baseline=root/"baseline.json"
            proof=root/"scored.json"
            self.assertEqual(cli([
                "score-source-context","export","--questions-out",str(questions),
                "--template-out",str(template)
            ]),0)
            self.assertEqual(json.loads(questions.read_text())["public_questions"],3)
            submission=json.loads(template.read_text())
            self.assertTrue(all(row["choice"] is None for row in submission["decisions"]))
            with self.assertRaises(SystemExit):
                cli([
                    "score-source-context","score",
                    "--predictions",str(template),"--out",str(proof)
                ])
            self.assertFalse(proof.exists())
            self.assertEqual(cli([
                "score-source-context","baseline","--strategy","always-ABSTAIN",
                "--out",str(baseline)
            ]),0)
            self.assertEqual(json.loads(baseline.read_text())["total_exact_source_derived_matches"],1)
            for row in submission["decisions"]:
                row["choice"]=self.truth[row["id"]]
            template.write_text(json.dumps(submission))
            self.assertEqual(cli([
                "score-source-context","score",
                "--predictions",str(template),"--out",str(proof)
            ]),0)
            result=json.loads(proof.read_text())
            self.assertEqual(result["total_exact_source_derived_matches"],3)
            self.assertEqual(result["candidate_origin"],"EXTERNAL_UNVERIFIED_PREDICTIONS")
            self.assertFalse(result["model_inference_performed_by_this_scorer"])

    def test_no_partial_export_overwrites_existing_question_or_template_file(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            q=root/"question.json"
            t=root/"template.json"
            q.write_text("PREVIOUS_DATA")
            with self.assertRaises(SystemExit):
                c.main(["export","--questions-out",str(q),"--template-out",str(t)])
            self.assertEqual(q.read_text(),"PREVIOUS_DATA")
            self.assertFalse(t.exists())

    def test_duplicate_candidate_json_keys_fail_closed(self):
        from falsum.phase5m_real_source_sensitive_model import read_json
        with self.assertRaises(c.DiagnosticError):
            read_json(b'{"decisions":[],"decisions":[{"id":"fake"}]}')


if __name__=="__main__":
    unittest.main()
