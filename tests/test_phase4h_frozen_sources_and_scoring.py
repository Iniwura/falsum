"""Phase 4H synthetic parser adversarial tests: not real upstream or model inference."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.phase4h_frozen_source import (
    validate_lock, git_blob, verify_locked_source, SourceError, LOCK_GIT_BLOB
)
from falsum.phase4h_real_model_probe import (
    load_source, make_inputs, audit, score_key, sha, ProbeError, INPUT_STATUS
)

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "data/phase4h-frozen-four-new-source-projects.json"


class FrozenSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw=LOCK.read_bytes()
        cls.lock=validate_lock(cls.raw)

    def dummy_verified_report(self):
        rows=[]
        for c in self.lock["cases"]:
            proof={}
            for rev in ("parent","fixed"):
                for kind in ("source","test"):
                    label=rev+"_"+kind
                    proof[label]={
                        "pinned_git_blob_sha1":c[label+"_blob"],
                        "downloaded_bytes_sha256":"a"*64,
                        "bytes":170,
                        "url":"https://raw.githubusercontent.com/"+c["repository"]+
                              "/"+c[rev]+"/"+c[kind+"_path"]
                    }
            rows.append({
                "project":c["key"],"upstream_repository":c["repository"],
                "fix_commit":c["fixed"],"direct_parent_commit":c["parent"],
                "source_file_modified_in_pinned_fix":True,
                "selected_test_file_modified_in_pinned_fix":c["test_changed_in_fix"],
                "source_before_and_after_anchor_verified":True,
                "test_added_anchor_verified":c["test_added_anchor"] is not None,
                "source_and_test_blobs":proof,
            })
        return {
            "schema_version":1,
            "status":"PHASE4H_FOUR_PUBLIC_NEW_PROJECT_SOURCE_COMMITS_AND_TESTS_VERIFIED_NOT_GOLD",
            "frozen_selection_git_blob":LOCK_GIT_BLOB,
            "frozen_selection_sha256":sha(self.raw),
            "source_repositories_verified":4,
            "source_revision_conditions":8,
            "source_parent_and_fix_file_blob_checks":16,
            "source_patches_verified":4,
            "selected_test_files_changed_in_fix":2,
            "selected_test_files_unchanged_in_fix":2,
            "commits_real_and_parent_verified":True,
            "downloaded_public_patches_executed":False,
            "independent_appsec_gold_labels":0,
            "new_eligible_anjoman_rows":0,
            "registered_evaluator":False,
            "model_scores_observed":False,
            "public_new_to_repo_not_blind_or_pretraining_disjoint":True,
            "projects":rows,
        }

    def test_committed_exact_manifest_precedes_any_model_outputs(self):
        self.assertEqual(git_blob(self.raw),LOCK_GIT_BLOB)
        self.assertEqual(self.lock["source_cases"],4)
        self.assertEqual(self.lock["revision_conditions"],8)
        self.assertEqual(self.lock["independent_appsec_adjudicated_labels"],0)
        self.assertFalse(self.lock["no_network_evaluator_registration"] is False)
        self.assertEqual([x["key"] for x in self.lock["cases"]],
                         ["pyjwt","werkzeug","mcp-python","pillow"])
        self.assertEqual(sum(x["test_changed_in_fix"] for x in self.lock["cases"]),2)

    def test_forged_or_altered_manifest_rejected(self):
        for key,value in (
            ("no_model_training_allowed",False),
            ("independent_appsec_adjudicated_labels",8),
            ("not_private_blind_holdout",False),
            ("revision_conditions",6),
        ):
            with self.subTest(key=key):
                source=copy.deepcopy(self.lock)
                source[key]=value
                with self.assertRaises(SourceError):
                    validate_lock(json.dumps(source).encode())

    def test_mock_source_proof_keeps_eight_balanced_author_hypotheses(self):
        fake=json.dumps(self.dummy_verified_report()).encode()
        _,_,cases=load_source(self.raw,fake)
        self.assertEqual(len(cases),8)
        self.assertEqual([r["source_based_author_expected"] for r in cases],
                         ["A","B"]*4)
        self.assertEqual([r["source_revision"] for r in cases],
                         ["parent","fixed"]*4)
        self.assertTrue(all(r["independent_appsec_gold"] is None for r in cases))

    def test_synthetic_tokenizer_and_official_score_packet_fail_closed(self):
        fake=json.dumps(self.dummy_verified_report()).encode()
        fake_tokenizer=b"synthetic-not-official-tokenizer"
        with patch("falsum.phase4h_real_model_probe.TOKENIZER_SHA256",sha(fake_tokenizer)):
            frozen=make_inputs(self.raw,fake,fake_tokenizer,
                               lambda rendered:[50281,1,2,3,4,50282])
            self.assertEqual(frozen["status"],INPUT_STATUS)
            self.assertEqual(len(frozen["inputs"]),16)
            self.assertEqual(len({x["id"] for x in frozen["inputs"]}),16)
            self.assertEqual(sum(x["source_author_expected"]=="A" for x in frozen["inputs"]),8)
            self.assertFalse(frozen["training_allowed"])
            bad_scores={x["id"]:{"invented":"not an official score packet"}
                        for x in frozen["inputs"]}
            with self.assertRaises(Exception):
                audit(self.raw,fake,frozen,bad_scores)
            changed=copy.deepcopy(frozen)
            changed["inputs"][0]["question_sha256"]="0"*64
            with self.assertRaises(ProbeError):
                audit(self.raw,fake,changed,bad_scores)
            changed=copy.deepcopy(frozen)
            changed["registered_evaluator"]=True
            with self.assertRaises(ProbeError):
                audit(self.raw,fake,changed,bad_scores)

    def test_fake_source_receipt_and_duplicate_key_rejected(self):
        source=self.dummy_verified_report()
        for kind in ("false_verified","expert_labels","changed_blob","wrong_test_delta"):
            fake=copy.deepcopy(source)
            if kind=="false_verified":
                fake["commits_real_and_parent_verified"]=False
            elif kind=="expert_labels":
                fake["independent_appsec_gold_labels"]=4
            elif kind=="changed_blob":
                fake["projects"][0]["source_and_test_blobs"]["parent_source"]["pinned_git_blob_sha1"]="0"*40
            else:
                fake["projects"][1]["selected_test_file_modified_in_pinned_fix"]=True
            with self.subTest(kind=kind):
                with self.assertRaises(ProbeError):
                    load_source(self.raw,json.dumps(fake).encode())

    def test_score_identifiers_are_bounded(self):
        self.assertEqual(score_key("mcp-python-fixed","A"),"mcp-python-fixed--A")
        for bad in ("/tmp/bad","../escape","a.x","SPACES",""):
            with self.subTest(bad=bad):
                with self.assertRaises(ProbeError):
                    score_key(bad,"A")


if __name__=="__main__":
    unittest.main()
