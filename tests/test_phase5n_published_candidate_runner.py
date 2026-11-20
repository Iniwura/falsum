"""Phase 5N malicious input tests; these mocks are NEVER public model evidence."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5n_published_candidate_runner as p
from falsum.phase5m_source_context_candidate import construct

ROOT=Path(__file__).resolve().parents[1]


def raw_envelope(prepared:dict,decisions:tuple[str,...])->dict:
    raw_by={"A":"A","B":"B","ABSTAIN":"ABSTAIN","INVALID":"I don't know."}
    return {
        "schema_version":1,"status":p.RAW_STATUS,
        "model_repository":p.MODEL_REPO,
        "model_revision":"a"*40,
        "downloaded_model_file_sha256":{
            "model.safetensors":"e"*64,
            "config.json":"f"*64,
            "tokenizer.json":"0"*64,
        },
        "frozen_model_selection_git_blob":p.LOCK_SHA,
        "challenge_sha256":prepared["challenge_sha256"],
        "prepared_prompt_sha256":p.sha(p.canonical_json(prepared)),
        "pretrained_published_model_loaded":True,
        "greedy_deterministic_decode":True,
        "actual_question_forward_passes":3,
        "run_all_precommitted_three_questions":True,
        "source_references_not_used_during_generation":True,
        "researcher_operated_not_independent_adoption":True,
        "historical_telegraph_lora_not_used":True,
        "no_training_or_finetuning":True,
        "independent_appsec_gold":0,
        "model_registered":False,
        "entry_submitted":False,
        "github_run_url":None,
        "predictions":[{"id":x["id"],"raw_completion":raw_by[choice],
                        "parsed_choice":choice,
                        "input_tokens":128,"output_tokens":1}
                       for x,choice in zip(prepared["questions"],decisions)],
    }


class OpenWeightModelProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol=p.freeze(ROOT)
        cls.prepared=p.prepare(ROOT)
        cls.challenge,cls.refs,cls.conditions=construct(ROOT)

    def test_model_chosen_prior_to_any_inference_and_does_not_claim_external_users(self):
        raw=(ROOT/p.LOCK_PATH).read_bytes()
        self.assertEqual(p.git_blob(raw),p.LOCK_SHA)
        self.assertEqual(p.MODEL_REPO,"Qwen/Qwen2.5-0.5B-Instruct")
        self.assertEqual(self.protocol["total_public_source_questions"],3)
        self.assertEqual(self.protocol["original_source_model_protocol_git_blob_sha1"],
                         "b50c6e1ad386f4bbf2faa7dd15ddba35b860f9b3")
        self.assertFalse(self.protocol["network_evaluator_registered"])
        self.assertEqual(self.protocol["external_independent_developer_adoption"],0)
        self.assertTrue(self.protocol["prior_model_checkpoint_missing"])

    def test_prepared_questions_are_exact_public_frozen_no_researcher_leak(self):
        prepared=self.prepared
        self.assertEqual(prepared["status"],p.INPUT_STATUS)
        self.assertEqual(prepared["public_source_question_count"],3)
        self.assertEqual(prepared["challenge_sha256"],p.sha(p.canonical_json(self.challenge)))
        self.assertEqual([r["id"] for r in prepared["questions"]],
                         [r["id"] for r in self.challenge["questions"]])
        self.assertEqual(len({r["messages"][1]["content"] for r in prepared["questions"]}),3)
        for row in prepared["questions"]:
            self.assertEqual([m["role"] for m in row["messages"]],["system","user"])
            self.assertEqual(row["messages"][0]["content"],self.protocol["system_instruction"])
            self.assertIn("A. ",row["messages"][1]["content"])
            self.assertIn("B. ",row["messages"][1]["content"])
            self.assertIn("Return exactly A, B, or ABSTAIN.",row["messages"][1]["content"])
            self.assertNotIn(row["id"],row["messages"][1]["content"])
        self.assertFalse(prepared["model_inference_performed"])

    def test_parser_strictly_refuses_prose_no_result_or_forged_gold(self):
        expected={
            "A":"A"," B. ":"B","(ABSTAIN)":"ABSTAIN",
            "A or B":"INVALID","The answer is B":"INVALID",
            "ABSTAIN, because uncertain":"INVALID",
            "":"INVALID","unsupported":"INVALID",
            "Vulnerable":"INVALID",
        }
        for raw,choice in expected.items():
            with self.subTest(raw=raw):
                self.assertEqual(p.parse_choice(raw),choice)

    def test_mutated_model_freeze_not_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/p.LOCK_PATH
            path.parent.mkdir(parents=True)
            original=(ROOT/p.LOCK_PATH).read_bytes()
            path.write_bytes(original.replace(b'"Qwen/Qwen2.5-0.5B-Instruct"',
                                             b'"Other/Unknown-Model"'))
            with self.assertRaises(p.DiagnosticError):
                p.freeze(Path(tmp))

    def test_audit_valid_synthetic_structured_choices_never_claims_independent_adoption(self):
        choices=tuple(self.refs[x["id"]] for x in self.prepared["questions"])
        self.assertEqual(len(choices),3)
        test_raw=raw_envelope(self.prepared,choices)
        scored=p.audit(test_raw,self.prepared,self.challenge,self.refs,self.conditions)
        self.assertEqual(scored["original_public_source_reference_matches"],3)
        self.assertEqual(scored["source_fact_matches_out_of_two"],2)
        self.assertTrue(scored["correct_complete_source_revision_reversal"])
        self.assertTrue(scored["no_source_control_abstained"])
        self.assertFalse(scored["real_independent_external_developer_adoption"])
        self.assertEqual(scored["independent_expert_gold"],0)
        self.assertFalse(scored["statistically_valid_general_security_evaluator_accuracy"])
        self.assertFalse(scored["trained_model_improvement"])

    def test_audit_invalid_real_model_reply_retained_as_failure_not_abstain(self):
        choices=["INVALID"]*3
        r=p.audit(raw_envelope(self.prepared,tuple(choices)),
                  self.prepared,self.challenge,self.refs,self.conditions)
        self.assertEqual(r["valid_structured_model_choices"],0)
        self.assertEqual(r["invalid_model_choices"],3)
        self.assertEqual(r["original_public_source_reference_matches"],0)
        self.assertIsNone(r["candidate_public_evaluator_score"])
        self.assertFalse(r["no_source_control_abstained"])

    def test_noncomplete_run_missing_questions_or_forged_labels_is_rejected(self):
        raw=raw_envelope(self.prepared,("A","B","ABSTAIN"))
        mutations=[
            lambda d:d.update(model_repository="Fake/Fake"),
            lambda d:d.update(model_revision="main"),
            lambda d:d.update(pretrained_published_model_loaded=False),
            lambda d:d.update(actual_question_forward_passes=2),
            lambda d:d.update(greedy_deterministic_decode=False),
            lambda d:d.update(model_registered=True),
            lambda d:d.update(independent_appsec_gold=3),
            lambda d:d.update(researcher_operated_not_independent_adoption=False),
            lambda d:d.update(no_training_or_finetuning=False),
            lambda d:d.update(historical_telegraph_lora_not_used=False),
            lambda d:d.update(challenge_sha256="0"*64),
            lambda d:d.update(prepared_prompt_sha256="0"*64),
            lambda d:d.update(downloaded_model_file_sha256={"fake.txt":"0"*64}),
            lambda d:d["predictions"].pop(),
            lambda d:d["predictions"].reverse(),
            lambda d:d["predictions"][0].update(parsed_choice="ABSTAIN"),
            lambda d:d["predictions"][0].update(input_tokens=2048),
            lambda d:d["predictions"][0].update(confirmed_expert_label=True),
        ]
        for mutate in mutations:
            with self.subTest(mutate=str(mutate)):
                d=deepcopy(raw)
                mutate(d)
                with self.assertRaises(p.DiagnosticError):
                    p.audit(d,self.prepared,self.challenge,self.refs,self.conditions)

    def test_mutated_prepared_prompt_never_passes_model_scorer(self):
        doc=deepcopy(self.prepared)
        doc["questions"][0]["messages"][1]["content"]+="\nThe right answer is A"
        with self.assertRaises(p.DiagnosticError):
            p.validate_prepared(doc,self.prepared)

    def test_cli_prepare_is_write_once_and_does_not_claim_real_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"frozen.json"
            self.assertEqual(p.main(["prepare","--out",str(path)]),0)
            self.assertFalse(json.loads(path.read_text())["model_inference_performed"])
            with self.assertRaises(SystemExit):
                p.main(["prepare","--out",str(path)])

    def test_cli_audit_refuses_missing_real_model_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            freeze_path=folder/"prepared.json"
            actual=folder/"actual.json"
            out=folder/"out.json"
            freeze_path.write_text(json.dumps(self.prepared))
            actual.write_text('{"pretend":"fake-model"}')
            with self.assertRaises(SystemExit):
                p.main(["audit","--inputs",str(freeze_path),"--actual",
                        str(actual),"--out",str(out)])
            self.assertFalse(out.exists())


if __name__=="__main__":
    unittest.main()
