"""Source-separated transfer cases, false-label quarantine, exact blob replay."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from falsum.phase2u_fresh_transfer import (
    FreshTransferError, construct, validate, PUBLIC, PRIVATE,
)
from falsum.real_fix_corpus import load_queue
from falsum.real_fix_replay import git_blob_sha, raw_url

ROOT=Path(__file__).resolve().parents[1]


def inputs():
    specs=json.loads((ROOT/"data/phase2u-fresh-transfer-cases.json").read_text())
    train=load_queue(ROOT/"data/real-fix-train-candidates.json")
    old=load_queue(ROOT/"data/real-fix-queue.json")
    prior=json.loads((ROOT/"data/advisory-queue.json").read_text())
    return specs,train,old,prior


class FreshTransferTests(unittest.TestCase):
    def setUp(self):
        self.spec,self.train,self.old,self.prior=inputs()

    def test_three_new_source_projects_dont_touch_training_or_previous_diagnostics(self):
        cases=validate(self.spec,self.train,self.old,self.prior)
        self.assertEqual(len(cases),3)
        old={x["repository"] for x in self.train["cases"]+self.old["cases"]}
        self.assertFalse(old&{x["repository"] for x in cases})
        self.assertEqual(len({x["repository"] for x in cases}),3)
        self.assertFalse(self.spec["network_eligible"])
        self.assertFalse(self.spec["heldout_sealed"])
        self.assertFalse(self.spec["model_training_authorized"])

    def test_fake_review_and_training_promotion_refused(self):
        for field,value in (("independent_human_reviews",1),("network_eligible",True),
                            ("heldout_sealed",True),("model_training_authorized",True),
                            ("research_only",False),("status","APPROVED")):
            with self.subTest(field=field):
                spec=copy.deepcopy(self.spec)
                spec[field]=value
                with self.assertRaises(FreshTransferError):
                    validate(spec,self.train,self.old,self.prior)

    def test_project_overlap_refused(self):
        spec=copy.deepcopy(self.spec)
        spec["cases"][0]["repository"]=self.old["cases"][0]["repository"]
        with self.assertRaisesRegex(FreshTransferError,"source-project overlap"):
            validate(spec,self.train,self.old,self.prior)

    def test_prior_ghsa_overlap_refused(self):
        spec=copy.deepcopy(self.spec)
        spec["cases"][0]["advisory"]="GHSA-cpwx-vrp4-4pq7"
        with self.assertRaisesRegex(FreshTransferError,"advisory reused"):
            validate(spec,self.train,self.old,self.prior)

    def test_spoofed_source_url_refused(self):
        spec=copy.deepcopy(self.spec)
        spec["cases"][0]["upstream_evidence"]="https://example.com/fake"
        with self.assertRaisesRegex(FreshTransferError,"provenance URL"):
            validate(spec,self.train,self.old,self.prior)

    def _offline_sources(self):
        spec=copy.deepcopy(self.spec)
        sources={}
        commits={}
        for i,row in enumerate(spec["cases"]):
            old_code=(f"def risky_{i}(value):\n    return value\n").encode()
            new_code=(f"def risky_{i}(value):\n    return str(value)\n").encode()
            old_test=(f"def test_case_{i}():\n    assert False\n").encode()
            new_test=(f"def test_case_{i}():\n    assert True\n").encode()
            row["source_blob"]=git_blob_sha(new_code)
            row["test_blob"]=git_blob_sha(new_test)
            patch=f"@@ -1,2 +1,2 @@\n def risky_{i}(value):\n-    return value\n+    return str(value)"
            test_patch=f"@@ -1,2 +1,2 @@\n def test_case_{i}():\n-    assert False\n+    assert True"
            files=[
                {"filename":row["source_path"],"sha":row["source_blob"],"status":"modified","patch":patch},
                {"filename":row["test_path"],"sha":row["test_blob"],"status":"modified","patch":test_patch},
            ]
            commits[row["id"]]={"sha":row["commit"],"parents":[{"sha":row["parent"]}],
                                 "html_url":row["upstream_evidence"],"files":files}
            for path,before,after in ((row["source_path"],old_code,new_code),
                                      (row["test_path"],old_test,new_test)):
                sources[raw_url(row["repository"],row["parent"],path)]=before
                sources[raw_url(row["repository"],row["commit"],path)]=after
        def commit_fetch(url):
            return next(v for v in commits.values() if v["sha"] in url)
        return spec,sources,commit_fetch

    def test_actual_replay_and_no_model_label_leakage(self):
        spec,sources,fetch=self._offline_sources()
        public,key=construct(spec,self.train,self.old,self.prior,fetch,sources.__getitem__)
        self.assertEqual(len(public["cases"]),6)
        self.assertEqual(len(key["entries"]),6)
        self.assertEqual(public["status"],PUBLIC)
        self.assertEqual(key["status"],PRIVATE)
        self.assertFalse(public["sealed_holdout"])
        self.assertFalse(public["training_authorized"])
        self.assertEqual(key["independent_human_reviews"],0)
        self.assertTrue(all(r["pre_and_post_files_verified"]==2 for r in key["verified_sources"]))
        payload=json.dumps(public)
        self.assertNotIn("ai_proposed_choice",payload)
        self.assertNotIn("fix_sha",payload)
        self.assertNotIn("GHSA-",payload)
        for i in (0,2,4):
            a,b=public["cases"][i:i+2]
            self.assertEqual({a["candidate_a"],a["candidate_b"]},{b["candidate_a"],b["candidate_b"]})
            self.assertNotEqual(key["entries"][i]["ai_proposed_kind"],key["entries"][i+1]["ai_proposed_kind"])

    def test_mutated_source_bytes_detected(self):
        spec,sources,fetch=self._offline_sources()
        row=spec["cases"][0]
        sources[raw_url(row["repository"],row["commit"],row["source_path"])]=b"changed\n"
        with self.assertRaises(FreshTransferError):
            construct(spec,self.train,self.old,self.prior,fetch,sources.__getitem__)

    def test_mutated_source_patch_detected(self):
        spec,sources,fetch=self._offline_sources()
        base=fetch("https://api.github.com/repos/tornadoweb/tornado/commits/"+spec["cases"][0]["commit"])
        base["files"][0]["patch"]=base["files"][0]["patch"].replace("str(value)","value")
        with self.assertRaises((FreshTransferError,ValueError)):
            construct(spec,self.train,self.old,self.prior,fetch,sources.__getitem__)


if __name__=="__main__":
    unittest.main()
