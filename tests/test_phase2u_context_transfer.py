"""Phase2U research-only transferred context training, with strict provenance."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.ai_review_benchmark import build
from falsum.phase2u_context_transfer import (
    TransferError, append_train, make_context_pairs,
)
from falsum.real_fix_corpus import load_queue

ROOT=Path(__file__).resolve().parents[1]


def fixtures():
    spec=json.loads((ROOT/"data/ai-review-train-candidate-drafts.json").read_text())
    queue=load_queue(ROOT/"data/real-fix-train-candidates.json")
    old=load_queue(ROOT/"data/real-fix-queue.json")
    prior=json.loads((ROOT/"data/advisory-queue.json").read_text())
    evidence={
        "status":"SOURCE_VERIFIED_LABELS_UNREVIEWED",
        "source_verified":4,
        "independent_human_reviews":0,
        "training_authorized":False,
        "network_eligible":False,
        "cases_sha256":"a"*64,
        "cases":[{"id":r["id"]} for r in queue["cases"]],
    }
    prompts=[]; refs=[]
    for i,source in enumerate(queue["cases"]):
        label="pristine-"+str(i)
        prompts.append({"challenge_id":label,
             "prompt":"Review the following original source excerpt for security concerns.\n\n"
                      "Source excerpt:\n"+chr(96)*3+"python\n"
                      "def originally_unpatched_source(value):\n    return value\n"
                      +chr(96)*3})
        refs.append({"challenge_id":label,"case_id":source["id"],"source_lines":[10,32]})
    with patch("falsum.ai_review_benchmark.build_challenges",return_value=(
            {"prompts":prompts},{"records":refs})):
        public,key=build(spec,queue,evidence)
    return public,key,old,queue,prior


class ContextTransferTests(unittest.TestCase):
    def setUp(self):
        self.pub,self.key,self.old,self.train,self.prior=fixtures()

    def test_training_only_8_pairs_four_disjoint_projects(self):
        rows,manifest=make_context_pairs(self.pub,self.key,self.old,self.train,self.prior)
        self.assertEqual(len(rows),8)
        self.assertEqual(len(manifest["training_projects"]),4)
        self.assertEqual(len(manifest["excluded_projects"]),4)
        self.assertFalse(set(manifest["training_projects"])&set(manifest["excluded_projects"]))
        self.assertEqual(manifest["independent_human_reviews"],0)
        self.assertTrue(manifest["prior_ai_draft_inspected"])
        self.assertFalse(manifest["network_eligible"])
        self.assertFalse(manifest["training_authorized_for_submission"])
        self.assertFalse(manifest["independent_accuracy_established"])
        self.assertFalse(manifest["external_evaluation_is_sealed"])
        self.assertEqual(len({r["rejected"] for r in rows}),8)
        self.assertEqual(len({r["prompt"] for r in rows}),8)
        for row in rows:
            self.assertIn("Assessment scope: fictional service",row["chosen"])
            self.assertIn("Assessment scope: fictional service",row["rejected"])
            self.assertNotEqual(row["chosen"],row["rejected"])
            self.assertNotIn("GHSA-",row["prompt"])

    def test_failed_when_public_source_changed(self):
        pub=copy.deepcopy(self.pub)
        pub["cases"][0]["question"]+=" tampered"
        with self.assertRaisesRegex(ValueError,"tampered"):
            make_context_pairs(pub,self.key,self.old,self.train,self.prior)

    def test_failed_when_key_invents_human_label(self):
        key=copy.deepcopy(self.key)
        key["entries"][0]["human_validated"]=True
        with self.assertRaises(ValueError):
            make_context_pairs(self.pub,key,self.old,self.train,self.prior)

    def test_failed_when_new_training_project_overlaps_old(self):
        altered=copy.deepcopy(self.train)
        altered["cases"][0]["repository"]=self.old["cases"][0]["repository"]
        with self.assertRaises(ValueError):
            make_context_pairs(self.pub,self.key,self.old,altered,self.prior)

    def test_failed_if_prior_advisory_training_overlap(self):
        prior=copy.deepcopy(self.prior)
        prior["advisories"][0]["id"]=self.train["cases"][0]["advisory"]
        with self.assertRaisesRegex(TransferError,"leaked"):
            make_context_pairs(self.pub,self.key,self.old,self.train,prior)

    def test_duplicate_negative_in_baseline_fails(self):
        rows,manifest=make_context_pairs(self.pub,self.key,self.old,self.train,self.prior)
        base=[{"prompt":f"base-test-prompt-{i}","chosen":f"base-good-{i}",
               "rejected":f"base-bad-{i}"} for i in range(52)]
        combined,report=append_train(base,rows,manifest)
        self.assertEqual(len(combined),60)
        self.assertEqual(report["new_research_context_train_rows"],8)
        base[0]["rejected"]=rows[0]["rejected"]
        with self.assertRaisesRegex(TransferError,"duplicate negative"):
            append_train(base,rows,manifest)

    def test_baseline_must_be_substantive_and_quarantined(self):
        rows,manifest=make_context_pairs(self.pub,self.key,self.old,self.train,self.prior)
        with self.assertRaises(TransferError):
            append_train([],rows,manifest)
        bad=copy.deepcopy(manifest)
        bad["network_eligible"]=True
        with self.assertRaises(TransferError):
            append_train([{"prompt":"a","chosen":"b","rejected":"c"}]*52,rows,bad)

    def test_reversals_do_not_use_original_four_projects(self):
        rows,manifest=make_context_pairs(self.pub,self.key,self.old,self.train,self.prior)
        for project in ("psf/requests","aio-libs/aiohttp","pallets/jinja","axios/axios"):
            self.assertNotIn(project,manifest["training_projects"])
        self.assertEqual(len(rows),8)


if __name__=="__main__":
    unittest.main()
