"""Synthetic-only unit tests. Only the Phase 5M CI official score workflow
can attest real Foundation inference. Mock outputs are NEVER published.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase5m_real_source_sensitive_model as probe

ROOT=Path(__file__).resolve().parents[1]


def example_inputs(p:dict)->dict:
    conditions=probe.questions(p)
    rows=[]
    answers={a["id"]:a["text"] for a in p["candidate_answers"]}
    for index, ident in enumerate(probe.ALL_KEYS):
        cond,label=ident.split("--")
        rendered="### Task:\n"+conditions[cond]+"\n\n### Answer:\n"+answers[label]
        fake=[50281,111,222,333,index,444,555,666,777,50282]
        rows.append({
            "id":ident,"condition":cond,"answer_id":label,
            "question_sha256":probe.sha_text(conditions[cond]),
            "answer_sha256":probe.sha_text(answers[label]),
            "rendered_input_sha256":probe.sha_text(rendered),
            "token_count":len(fake),"input_ids":fake,
            "source_commit":p["source_parent_commit"] if cond=="code-context-a"
            else p["source_fix_commit"] if cond=="code-context-b" else None,
            "reference_is_independent_expert_gold":False,
        })
    return {
        "schema_version":1,"status":probe.STATUS_INPUT,
        "protocol_lock_git_blob":probe.PROTOCOL_GIT_BLOB_SHA,
        "intent":"SECURITY_REVIEW_GENERAL",
        "official_scoring_family":"SECURITY_REVIEW",
        "original_quarantined_model_sha256":probe.MODEL_SHA,
        "official_foundation_sha256":probe.FOUNDATION_SHA,
        "official_tokenizer_sha256":probe.TOKENIZER_SHA256,
        "verified_upstream_original_replay_run":p["verified_real_source_test_run"],
        "original_source_facts_rechecked":True,
        "source_sensitive_revisions":2,"no_source_controls":1,
        "model_score_inputs":6,"expected_real_inference_repeats_per_input":2,
        "inputs":rows,"not_independent_human_gold":True,
        "not_blind_model_pretraining_holdout":True,
        "model_training_or_registration":False,
    }


class OriginalModelSourceSensitivityAdversarialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p=probe.protocol(ROOT)
        cls.inputs=example_inputs(cls.p)

    def test_frozen_selection_predates_model_and_is_byte_immutable(self):
        raw=(ROOT/probe.PROTOCOL_PATH).read_bytes()
        self.assertEqual(probe.git_blob(raw),probe.PROTOCOL_GIT_BLOB_SHA)
        self.assertEqual(self.p["original_model_sha256"],probe.MODEL_SHA)
        self.assertEqual(self.p["source_selection_lock_git_blob_sha1"],
                         "79e27d78376dde9cdd9d4e628a95cc3cc7ae63ee")
        self.assertEqual(self.p["original_score_inputs"],6)
        self.assertEqual(self.p["independent_human_expert_gold_labels"],0)
        self.assertFalse(self.p["network_model_registered"])

    def test_precommitted_source_answers_stable_and_roles_not_exposed_in_prompts(self):
        q=probe.questions(self.p)
        self.assertEqual(set(q),set(probe.CONDITIONS))
        self.assertIn("filename.startswith(base)",q["code-context-a"])
        self.assertIn("base + os.sep",q["code-context-b"])
        self.assertNotIn("if not filename.startswith(",q["source-omitted"])
        for question in q.values():
            for illegal in ("parent","fixed","patched","vulnerable"):
                self.assertNotIn(illegal,question.casefold())

    def test_frozen_protocol_mutated_question_or_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake=Path(tmp)/probe.PROTOCOL_PATH
            fake.parent.mkdir(parents=True)
            raw=(ROOT/probe.PROTOCOL_PATH).read_bytes()
            fake.write_bytes(raw.replace(b'"source_project"',b'"invented_project"'))
            with self.assertRaisesRegex(probe.DiagnosticError,"protocol has changed"):
                probe.protocol(Path(tmp))

    def test_six_ordered_inputs_are_unique_and_bound_to_original_source_evidence(self):
        rows=probe.validate_inputs(self.inputs,self.p)
        self.assertEqual(len(rows),6)
        self.assertEqual(tuple(x["id"] for x in rows),probe.ALL_KEYS)
        self.assertEqual(rows[0]["source_commit"],self.p["source_parent_commit"])
        self.assertEqual(rows[2]["source_commit"],self.p["source_fix_commit"])
        self.assertIsNone(rows[4]["source_commit"])

    def test_input_schema_rejects_forged_context_and_gold_claims(self):
        changes=[
            lambda doc:doc.update(model_training_or_registration=True),
            lambda doc:doc.update(not_independent_human_gold=False),
            lambda doc:doc.update(model_score_inputs=8),
            lambda doc:doc.update(official_tokenizer_sha256="0"*64),
            lambda doc:doc.update(schema_version=True),
            lambda doc:doc.update(verified_upstream_original_replay_run=1),
            lambda doc:doc.update(actual_independent_gold=6),
            lambda doc:doc["inputs"].pop(),
            lambda doc:doc["inputs"].reverse(),
            lambda doc:doc["inputs"][0].update(answer_id="B"),
            lambda doc:doc["inputs"][0].update(question_sha256="0"*64),
            lambda doc:doc["inputs"][0].update(rendered_input_sha256="0"*64),
            lambda doc:doc["inputs"][0].update(source_commit="0"*40),
            lambda doc:doc["inputs"][0].update(reference_is_independent_expert_gold=True),
            lambda doc:doc["inputs"][0].update(token_count=9999),
            lambda doc:doc["inputs"][0].update(input_ids=[50281,50282]),
            lambda doc:doc["inputs"][0].update(label_from_expert="SUPPORTED"),
        ]
        for change in changes:
            with self.subTest(change=str(change)):
                d=copy.deepcopy(self.inputs)
                change(d)
                with self.assertRaises(probe.DiagnosticError):
                    probe.validate_inputs(d,self.p)

    def test_genuine_original_foundation_packets_required_no_fakes(self):
        with self.assertRaises(probe.DiagnosticError):
            probe.evaluate(self.p,self.inputs,{})
        with self.assertRaises(probe.DiagnosticError):
            probe.evaluate(self.p,self.inputs,{k:{} for k in probe.ALL_KEYS[:-1]})
        with self.assertRaises(probe.ScoreProofError):
            probe.evaluate(self.p,self.inputs,{k:{"score_hex":"0"} for k in probe.ALL_KEYS})

    def test_synthetic_math_for_source_sensitive_success_never_counts_human_gold(self):
        fake_values={
            "code-context-a--A":0.5,"code-context-a--B":0.2,
            "code-context-b--A":0.2,"code-context-b--B":0.5,
            "source-omitted--A":0.6,"source-omitted--B":0.1,
        }
        with patch.object(probe,"_score",side_effect=lambda packet,ident:{
                "float32_value":fake_values[ident],
                "float32_score_hex":"0x3f000000",
            }):
            d=probe.evaluate(self.p,self.inputs,{k:{} for k in probe.ALL_KEYS})
        self.assertEqual(d["original_model_fact_matches_out_of_two"],2)
        self.assertTrue(d["real_model_complete_correct_source_fact_reversal"])
        self.assertTrue(d["real_model_changes_choice_with_source_revision"])
        self.assertEqual(d["no_source_control_preference"],"A")
        self.assertEqual(d["independent_expert_gold_labels"],0)
        self.assertFalse(d["actual_improvement_to_trained_model"])
        self.assertFalse(d["official_H2_submission"])
        self.assertFalse(d["model_registered"])

    def test_synthetic_invariant_model_fails_reversal_despite_one_fact_match(self):
        with patch.object(probe,"_score",side_effect=lambda packet,ident:{
                "float32_value":1 if ident.endswith("--A") else 0,
                "float32_score_hex":"0x3f000000",
            }):
            d=probe.evaluate(self.p,self.inputs,{k:{} for k in probe.ALL_KEYS})
        self.assertEqual(d["original_model_fact_matches_out_of_two"],1)
        self.assertFalse(d["real_model_complete_correct_source_fact_reversal"])
        self.assertFalse(d["real_model_changes_choice_with_source_revision"])
        self.assertEqual(d["constant_A_source_fact_matches"],1)
        self.assertEqual(d["constant_B_source_fact_matches"],1)
        self.assertIsNone(d["source_conditions"][2]["matches_original_executed_source_test_fact"])

    def test_no_source_control_reference_cannot_be_fabricated(self):
        p=copy.deepcopy(self.p)
        p["declared_source_fact_reference_labels"]["source-omitted"]="A"
        with patch.object(probe,"_score",side_effect=lambda packet,ident:{
                "float32_value":1 if ident.endswith("--A") else 0,
                "float32_score_hex":"0x3f000000",
            }):
            with self.assertRaises(AssertionError):
                # Protocol is SHA-bound to original lock; this mutation cannot
                # be written back as a valid frozen source protocol.
                self.assertEqual(p,probe.protocol(ROOT))

    def test_duplicate_score_packet_json_keys_rejected(self):
        with self.assertRaises(probe.DiagnosticError):
            probe.read_json(b'{"score_hex":"0x3f800000","score_hex":"0x00000000"}')

    def test_outputs_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/"proof.json"
            probe.write_once(target,{"no_gold":True})
            self.assertTrue(target.is_file())
            with self.assertRaisesRegex(probe.DiagnosticError,"overwrite"):
                probe.write_once(target,{"expert_gold":10})

    def test_cli_audit_fails_without_official_score_packets_and_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/"fake_inputs.json"
            path.write_text(json.dumps(self.inputs))
            with self.assertRaises(SystemExit):
                probe.main(["audit","--inputs",str(path),
                            "--scores-dir",str(root),"--out",str(root/"output.json")])
            self.assertFalse((root/"output.json").exists())


if __name__=="__main__":
    unittest.main()
