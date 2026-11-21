"""Phase 5W: strict model/output contract unit tests, NOT model inference evidence."""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from falsum import phase5w_original_new_source_model as w
from falsum import phase5u_project_disjoint_security as u
from falsum.phase5m_real_source_sensitive_model import ROOT, sha, canonical_json
from falsum.phase5l_pymdown_upstream_replay import git_blob


def fake_unit_test_fixture():
    """Deliberately synthetic metadata. Must NEVER enter release evidence."""
    refs={}
    questions=[]
    for project in u.PROJECTS:
        for revision in u.REVISIONS:
            for pos in u.POSITIONS:
                ident=u.ident(project,revision,pos)
                answers=("ABSTAIN" if revision=="source-omitted"
                         else "A" if (revision=="parent")==(
                             pos=="original-order") else "B")
                refs[ident]=answers
                questions.append({"id":ident})
    doc={"questions":questions}
    rows=[{"id":x["id"],"input_tokens":40,"output_tokens":2,
           "raw_completion":"ABSTAIN","parsed_choice":"ABSTAIN"}
          for x in questions]
    fake={
        "schema_version":1,"status":w.ST_RAW,
        "model_repository":w.MODEL_REPO,
        "original_publisher_immutable_revision":w.MODEL_REVISION,
        "original_publisher_files_sha256":{
            "model.safetensors":w.MODEL_SAFETENSORS_SHA256,
            "tokenizer.json":"a"*64,
            "config.json":"b"*64
        },
        "original_model_safetensors_sha256":w.MODEL_SAFETENSORS_SHA256,
        "preinference_protocol_git_blob_sha1":w.FROZEN_BLOB,
        "new_project_original_source_lock_git_blob_sha1":w.SOURCE_GIT_BLOB,
        "original_source_challenge_sha256":sha(canonical_json(doc)),
        "actual_original_published_model_forward_passes":24,
        "actual_model_loaded_from_original_publisher":True,
        "no_few_shot_or_prompt_tuning":True,
        "greedy_decode":True,
        "original_input_questions_unchanged":True,
        "researcher_operated_not_independent_review":True,
        "independent_appsec_gold_count":0,
        "registered_network_evaluator":False,
        "new_paid_telegraph_requests":0,
        "h2_officially_submitted":False,
        "original_github_run_url":None,
        "predictions":rows,
    }
    return doc,refs,fake


class RealOriginalPublisherProtocol(unittest.TestCase):
    def test_freeze_before_original_model_scoring(self):
        protocol=w.frozen()
        self.assertEqual(git_blob((ROOT/w.FROZEN_FILE).read_bytes()),w.FROZEN_BLOB)
        self.assertEqual(protocol["source_projects"],list(u.PROJECTS))
        self.assertEqual(protocol["model_forward_passes_required"],24)
        self.assertEqual(protocol["pinned_original_publisher_revision"],w.MODEL_REVISION)
        self.assertEqual(protocol["pinned_original_safetensors_sha256"],
                         w.MODEL_SAFETENSORS_SHA256)
        self.assertEqual(protocol["actual_source_original_git_files"],8)
        self.assertEqual(protocol["actual_test_original_git_files"],8)
        self.assertEqual(protocol["independent_appsec_expert_gold_count"],0)
        self.assertFalse(protocol["registered_network_evaluator"])
        self.assertTrue(protocol["no_model_score_or_positive_result_asserted_before_actual_inference"])

    def test_public_unit_test_simulation_not_actual_inference(self):
        doc,refs,raw=fake_unit_test_fixture()
        measured=w.audit(doc,refs,raw)
        self.assertEqual(measured["actual_original_model_forward_passes"],24)
        self.assertEqual(measured["measured_original_public_model"]
                         ["matches_to_researcher_derived_public_references"],8)
        self.assertEqual(measured["measured_original_public_model"]
                         ["source_present_matches"],0)
        self.assertEqual(measured["measured_original_public_model"]
                         ["source_absent_correct_abstention"],8)
        self.assertEqual(measured["actual_complete_source_and_answer_order_reversals"],0)
        self.assertEqual(measured["prompt_only_source_blind_disclosed_synthetic"]
                         ["matches_to_researcher_derived_public_references"],16)
        self.assertEqual(measured["always_abstain_disclosed_synthetic"]
                         ["matches_to_researcher_derived_public_references"],8)
        self.assertEqual(measured["published_model_vs_blind_reference_match_delta"],-8)
        self.assertEqual(measured["independent_appsec_expert_gold"],0)
        self.assertFalse(measured["registered_telegraph_evaluator"])
        # Fake fixtures are ONLY used to test auditor structure, never
        # written into any public model artifact. Actual scoring is the CI
        # infer+audit sequence with original immutable publisher weights.

    def test_wrong_publisher_revision_sha_or_hidden_gold_rejected(self):
        original,refs,raw=fake_unit_test_fixture()
        cases=[]
        for path,val in (
            ("model_repository","Local-Notebook-Model"),
            ("original_publisher_immutable_revision","0"*40),
            ("original_model_safetensors_sha256","0"*64),
            ("preinference_protocol_git_blob_sha1","0"*40),
            ("new_project_original_source_lock_git_blob_sha1","0"*40),
            ("original_source_challenge_sha256","0"*64),
            ("actual_original_published_model_forward_passes",23),
            ("actual_model_loaded_from_original_publisher",False),
            ("no_few_shot_or_prompt_tuning",False),
            ("greedy_decode",False),
            ("independent_appsec_gold_count",1),
            ("registered_network_evaluator",True),
            ("h2_officially_submitted",True),
        ):
            bad=deepcopy(raw);bad[path]=val;cases.append(bad)
        wrong=deepcopy(raw)
        wrong["original_publisher_files_sha256"]["model.safetensors"]="c"*64
        cases.append(wrong)
        for data in cases:
            with self.assertRaises((ValueError,TypeError)):
                w.audit(original,refs,data)

    def test_missing_swapped_invalid_raw_completions_rejected(self):
        doc,refs,raw=fake_unit_test_fixture()
        tests=[]
        for mutation in (
            lambda x:x["predictions"].pop(),
            lambda x:x["predictions"].reverse(),
            lambda x:x["predictions"][0].update(id="wrong"),
            lambda x:x["predictions"][0].update(input_tokens=1025),
            lambda x:x["predictions"][0].update(output_tokens=13),
            lambda x:x["predictions"][0].update(raw_completion="A"),
            lambda x:x["predictions"][0].update(parsed_choice="PASS"),
            lambda x:x["predictions"][0].update(secret_gold=True),
        ):
            corrupt=deepcopy(raw);mutation(corrupt);tests.append(corrupt)
        for bad in tests:
            with self.assertRaises((ValueError,TypeError)):
                w.audit(doc,refs,bad)

    def test_preinference_git_blob_byte_tampering_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            path=root/w.FROZEN_FILE
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes((ROOT/w.FROZEN_FILE).read_bytes()+b" ")
            with self.assertRaises(ValueError):
                w.frozen(root)

    def test_write_once_model_output_and_scored_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"raw-original-model.json"
            w.write_once(path,{"unit_test_only":True})
            with self.assertRaises(ValueError):
                w.write_once(path,{"replaced":True})


if __name__=="__main__":
    unittest.main()
