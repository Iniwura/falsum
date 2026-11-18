"""Synthetic adversarial tests for FOUR-RECEIPT real-source evidence index.

No synthetic source receipt is passed off as real upstream execution.
The separate GitHub Actions workflow downloads four *actual* immutable Actions
artifacts produced by the real upstream project test executions.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum.phase4p_open_source_review import load_lock
from falsum import phase4t_four_stage_evidence as t

ROOT=Path(__file__).resolve().parents[1]
LOCK=(ROOT/"data/phase4p-three-project-open-review-lock.json").read_bytes()
MANIFEST=(ROOT/"data/phase4t-four-run-receipt-lock.json").read_bytes()


def dumps(obj:dict)->bytes:
    return (json.dumps(obj,sort_keys=True,separators=(",",":"))+"\n").encode("utf-8")


def sample_receipts():
    manifest=t.validate_manifest(MANIFEST)
    lock=load_lock(LOCK)
    metas={}
    for k,v in manifest["runs"].items():
        metas[k]={
            "databaseId":v["id"],"headSha":v["head_sha"],
            "status":"completed","conclusion":"success",
            "event":v["event"],"workflowName":v["name"],
            "url":f"https://github.com/Iniwura/falsum/actions/runs/{v['id']}",
        }
    proof={}
    for e in manifest["receipts"]:
        row,s=t.stage_lookup(lock,e)
        sha_record={"first":"a"*64,"second":"b"*64,"third":"c"*64}
        if e["kind"]=="phase4r":
            data={
                "schema_version":1,"status":t.PHASE4R_STATUS,
                "target":e["target"],
                "upstream_repository":row["repository"],
                "security_family":row["security_family"],
                "baseline_upstream_parent_tests_passed":True,
                "fixed_implementation_test_fails_on_parent":True,
                "exact_pinned_fixed_source_security_regression_passed":True,
                "real_upstream_runtime_tests_executed":True,
                "regression_is_from_fixed_commit_not_a_homebrew_answer_key":True,
                "independent_human_appsec_labels":0,"new_anjoman_evaluation_rows":0,
                "original_model_improvement_proven":False,
                "network_evaluator_registered":False,
                "official_judge_certification":False,
                "raw_log_sha256":sha_record,
                "exit_statuses":{
                    "parent_original_upstream_tests":0,
                    "parent_with_fixed_security_regression":1,
                    "fixed_with_security_regression":0,
                },
                "upstream_source_and_test_provenance":{
                    "parent_original_source_commit":s["parent"],
                    "fixed_source_commit":s["fix"],
                    "parent_with_fixed_regression_overlay":{
                        "git_identity_checked":True,
                        "commit_sha":s["parent"],
                        "source_blob_sha1":s["parent_source_blob"],
                        "executed_test_blob_sha1":s["fixed_test_blob"],
                        "test_was_copied_from_pinned_fixed_upstream":True,
                    },
                    "fixed_original_test":{
                        "git_identity_checked":True,
                        "commit_sha":s["fix"],
                        "source_blob_sha1":s["fixed_source_blob"],
                        "executed_test_blob_sha1":s["fixed_test_blob"],
                        "test_was_copied_from_pinned_fixed_upstream":False,
                    },
                },
            }
        else:
            data={
                "schema_version":1,"status":t.PHASE4S_STATUS,
                "repair_stage":e["target"],"project":row["repository"],
                "source_case":row["id"],"original_source_commit":s["parent"],
                "fixed_source_commit":s["fix"],
                "real_original_upstream_python_tests_executed":True,
                "new_security_test_not_passing_old":True,
                "new_security_test_passing_fixed":True,
                "original_functionality_control_passed":True,
                "parent_failure_matched_missing_valueerror_not_dependency_error":True,
                "one_security_patch_not_assumed_complete_without_followup":True,
                "independently_verified_expert_gold":0,
                "new_anjoman_eligible_rows":0,
                "trained_evaluator_adapter":False,
                "improved_model_performance_proven":False,
                "real_deployed_file_access_proven":False,
                "logs_sha256":sha_record,
                "exit_statuses":{
                    "parent-original":0,"parent-new-regression":1,
                    "fixed-new-regression":0,
                },
                "actual_upstream_source_and_test_byte_identities":{
                    "parent_with_new_regression":{
                        "exact_checkout":s["parent"],
                        "original_source":{"git_blob_sha1":s["parent_source_blob"]},
                        "executed_upstream_test":{"git_blob_sha1":s["fixed_test_blob"]},
                        "parent_regression_test_overlaid_only":True,
                    },
                    "fixed_with_new_regression":{
                        "exact_checkout":s["fix"],
                        "original_source":{"git_blob_sha1":s["fixed_source_blob"]},
                        "executed_upstream_test":{"git_blob_sha1":s["fixed_test_blob"]},
                        "parent_regression_test_overlaid_only":False,
                    },
                },
            }
        proof[e["id"]]=dumps(data)
    return manifest,metas,proof


class FourSourceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.manifest,self.metas,self.receipts=sample_receipts()

    def test_four_real_source_receipt_shapes_one_judge_index_not_model_accuracy(self):
        output=t.aggregate(LOCK,MANIFEST,self.metas,self.receipts)
        self.assertEqual(output["distinct_upstream_repositories"],3)
        self.assertEqual(output["historical_distinct_fixed_commit_stages"],4)
        self.assertEqual(output["actual_upstream_original_pass_parent_new_test_fail_fixed_new_test_pass"],4)
        self.assertEqual(output["source_grounded_open_review_questions"],6)
        self.assertEqual(output["intent_id"],"SECURITY_REVIEW_GENERAL")
        self.assertEqual(output["status"],t.STATUS)
        self.assertEqual(output["independent_human_appsec_gold_labels"],0)
        self.assertEqual(output["new_anjo_network_evaluation_rows"],0)
        self.assertFalse(output["trained_model_improvement_proven"])
        self.assertFalse(output["live_network_evaluator_registered"])
        self.assertFalse(output["official_hackathon_submission_confirmed"])
        self.assertFalse(output["phase4o_author_written_a_b_material_promotion_allowed"])
        self.assertEqual(len(output["receipts"]),4)
        self.assertEqual(set(x["source_case"] for x in output["receipts"]),
                         {r["id"] for r in load_lock(LOCK)["cases"]})
        self.assertEqual(list(output["two_verified_public_github_workflow_runs"]),
                         ["phase4r","phase4s"])

    def test_historical_source_or_fixed_regression_test_mutation_cannot_be_accepted(self):
        for source_case in self.receipts:
            for field in ("source","test"):
                proof=copy.deepcopy(self.receipts)
                x=json.loads(proof[source_case])
                if x["status"]==t.PHASE4R_STATUS:
                    obj=x["upstream_source_and_test_provenance"]["parent_with_fixed_regression_overlay"]
                    key="source_blob_sha1" if field=="source" else "executed_test_blob_sha1"
                else:
                    obj=x["actual_upstream_source_and_test_byte_identities"]["fixed_with_new_regression"]
                    obj=obj["original_source"] if field=="source" else obj["executed_upstream_test"]
                    key="git_blob_sha1"
                obj[key]="0"*40
                proof[source_case]=dumps(x)
                with self.subTest(source_case=source_case,field=field):
                    with self.assertRaises(t.ProvenanceError):
                        t.aggregate(LOCK,MANIFEST,self.metas,proof)

    def test_false_pass_or_nonsecurity_failure_cannot_be_accepted(self):
        for key in self.receipts:
            proof=copy.deepcopy(self.receipts);x=json.loads(proof[key])
            status=x["exit_statuses"]
            status[("parent_with_fixed_security_regression" if x["status"]==t.PHASE4R_STATUS
                    else "parent-new-regression")]=0
            proof[key]=dumps(x)
            with self.subTest(key=key),self.assertRaises(t.ProvenanceError):
                t.aggregate(LOCK,MANIFEST,self.metas,proof)

    def test_no_unreviewed_source_forged_into_running_repo(self):
        doc=json.loads(MANIFEST)
        for mutation in (
            lambda x:x["receipts"].append(x["receipts"][0]),
            lambda x:x["receipts"][0].update(target="pyjwt"),
            lambda x:x["receipts"][1].update(run="phase4s"),
            lambda x:x["runs"]["phase4s"].update(id=2),
            lambda x:x.update(no_human_expert_gold_labels=False),
            lambda x:x["receipts"][0].update(file="../../private.txt"),
        ):
            d=copy.deepcopy(doc);mutation(d)
            with self.assertRaises(t.ProvenanceError):
                t.validate_manifest(dumps(d))

    def test_github_run_metadata_exact_sha_conclusion_and_workflow_mandatory(self):
        for run in self.metas:
            for field,bad in (
                ("databaseId",1),("headSha","0"*40),("conclusion","failure"),
                ("status","in_progress"),("event","workflow_dispatch"),
                ("workflowName","fake custom workflow"),
                ("url","https://evil.invalid/attacker"),
            ):
                meta=copy.deepcopy(self.metas);meta[run][field]=bad
                with self.subTest(run=run,field=field),self.assertRaises(t.ProvenanceError):
                    t.aggregate(LOCK,MANIFEST,meta,self.receipts)

    def test_fake_expert_labels_or_network_submission_claim_refused(self):
        for key in self.receipts:
            proof=copy.deepcopy(self.receipts);x=json.loads(proof[key])
            index_field=("independent_human_appsec_labels" if x["status"]==t.PHASE4R_STATUS
                         else "independently_verified_expert_gold")
            x[index_field]=1
            proof[key]=dumps(x)
            with self.subTest(key=key),self.assertRaises(t.ProvenanceError):
                t.aggregate(LOCK,MANIFEST,self.metas,proof)

    def test_no_duplicate_missing_or_extra_artifacts(self):
        for mutate in ("omit","add"):
            proof=dict(self.receipts)
            if mutate=="omit": proof.pop("koa-redirect")
            else: proof["surprise-private-answer"]=b"secret"
            with self.assertRaises(t.ProvenanceError):
                t.aggregate(LOCK,MANIFEST,self.metas,proof)

    def test_invalid_private_or_non_json_input_fails_and_not_echoed(self):
        proof=dict(self.receipts)
        proof["langchain-path"]=b"SECRET PRIVATE PROMPT NOT PUBLIC JSON"
        with self.assertRaisesRegex(t.ProvenanceError,"invalid JSON"):
            t.aggregate(LOCK,MANIFEST,self.metas,proof)

    def test_write_once_report_and_no_private_answer_material(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"runs").mkdir();(root/"receipts").mkdir()
            (root/"lock.json").write_bytes(LOCK)
            (root/"manifest.json").write_bytes(MANIFEST)
            for key,meta in self.metas.items():
                (root/"runs"/(key+".json")).write_bytes(dumps(meta))
            for item in self.manifest["receipts"]:
                folder=root/"receipts"/item["id"];folder.mkdir()
                (folder/item["file"]).write_bytes(self.receipts[item["id"]])
            args=["--lock",str(root/"lock.json"),
                  "--manifest",str(root/"manifest.json"),
                  "--runs-dir",str(root/"runs"),
                  "--receipts-dir",str(root/"receipts"),
                  "--out",str(root/"output.json")]
            self.assertEqual(t.main(args),0)
            doc=json.loads((root/"output.json").read_text())
            self.assertEqual(doc["actual_upstream_original_pass_parent_new_test_fail_fixed_new_test_pass"],4)
            self.assertNotIn("SENSITIVE",json.dumps(doc))
            self.assertNotIn("A/B winner",json.dumps(doc))
            with self.assertRaises(SystemExit):
                t.main(args)

    def test_rejects_unauthenticated_or_missing_source_lock(self):
        with self.assertRaises(Exception):
            t.aggregate(b'{"cases":[]}',MANIFEST,self.metas,self.receipts)

if __name__=="__main__":
    unittest.main()
