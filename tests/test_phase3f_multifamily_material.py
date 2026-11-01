"""Phase3F: real Git fix/test provenance and 7 vulnerability families, no labels."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from falsum.phase2w_proof_gate import ProofError
from falsum.real_fix_corpus import load_queue, RealFixError
from falsum.phase3f_multifamily_material import generate,PINS,PROMPTS,STATUS

ROOT=Path(__file__).resolve().parents[1]


def inputs():
    old=load_queue(ROOT/"data/real-fix-queue.json")
    train=load_queue(ROOT/"data/real-fix-train-candidates.json")
    catalog=json.loads((ROOT/"data/phase2w-applicability-rules.json").read_text())
    return old,train,catalog


def mock_commit(url):
    old,train,_=inputs()
    for row in old["cases"]+train["cases"]:
        if url.endswith("/"+row["commit"]):
            return {
                "sha":row["commit"],
                "html_url":f'https://github.com/{row["repository"]}/commit/{row["commit"]}',
                "parents":[{"sha":row["parent"]}],
                "files":[
                    {"filename":row["source_path"],"sha":row["source_blob"],"status":"modified",
                     "patch":"@@ -1,2 +1,2 @@\n-unsafe\n+safer\n context"},
                    {"filename":row["test_path"],"sha":row["test_blob"],"status":"modified",
                     "patch":"@@ -1,2 +1,2 @@\n-old test\n+new regression test\n context"}
                ]
            }
    raise AssertionError("unexpected GitHub commit URL")


class DiverseSourceMaterialTests(unittest.TestCase):
    def test_real_source_ids_are_seven_non_aiohttp_non_fresh(self):
        self.assertEqual(len(PINS),7)
        self.assertEqual(len(set(p[0] for p in PINS)),7)
        self.assertEqual(len(set(p[1] for p in PINS)),7)
        self.assertTrue(all(not p[0].startswith("fresh-") and "aiohttp" not in p[0] for p in PINS))
        self.assertEqual(len(PROMPTS),7)

    def test_eight_verified_source_commits_seven_review_families(self):
        d=generate(*inputs(),fetcher=mock_commit)
        self.assertEqual(d["status"],STATUS)
        self.assertEqual(d["external_source_revisions_verified"],8)
        self.assertEqual(d["external_source_and_test_file_blob_pairs_verified"],8)
        self.assertEqual(d["review_cases"],7)
        self.assertEqual(d["distinct_security_families"],7)
        self.assertEqual(len(d["review_packets"]),7)
        self.assertEqual(len({r["security_family"] for r in d["review_packets"]}),7)
        self.assertFalse(d["fresh_project_holdout_reused"])
        self.assertEqual(d["independent_human_labels"],0)
        self.assertEqual(d["accepted_training_pairs"],0)
        self.assertFalse(d["network_eligible"])

    def test_draft_answers_have_sha_and_no_trainer_labels(self):
        r=generate(*inputs(),fetcher=mock_commit)
        for p in r["review_packets"]:
            self.assertIsNone(p["human_preference"])
            self.assertFalse(p["human_review_verified"])
            self.assertFalse(p["network_eligible"])
            self.assertFalse(p["training_authorized"])
            self.assertFalse(p["source_patch_is_exploit_proof"])
            self.assertFalse(p["production_app_version_known"])
            self.assertFalse(p["production_traffic_exposure_known"])
            self.assertFalse(p["candidate_order_human_randomized"])
            self.assertEqual(len(p["unreviewed_candidates"]),2)
            self.assertEqual([x["id"] for x in p["unreviewed_candidates"]],["A","B"])
            for c in p["unreviewed_candidates"]:
                self.assertEqual(c["sha256"],hashlib.sha256(c["text"].encode()).hexdigest())
                self.assertNotIn("independent_expert_approved",c)
            self.assertIn(p["fix_commit"],p["fix_commit_url"])
            self.assertIn(p["source_post_fix_git_blob_sha1"],[pin[3] for pin in PINS])

    def test_alternating_author_preference_is_not_public_ground_truth(self):
        prefs=[PROMPTS[p[0]][1] for p in PINS]
        self.assertGreaterEqual(prefs.count("A"),2)
        self.assertGreaterEqual(prefs.count("B"),2)
        rendered=json.dumps(generate(*inputs(),fetcher=mock_commit))
        self.assertNotIn('"author_expected"',rendered)
        self.assertNotIn('"correct_answer"',rendered)

    def test_original_source_commit_identity_tampering_refused(self):
        for field in ("repository","commit","source_blob","test_blob"):
            with self.subTest(field=field):
                old,train,cat=inputs()
                target=old["cases"][0]
                target[field]="0"*40 if field!="repository" else "some/other"
                with self.assertRaises((ProofError,RealFixError)):
                    generate(old,train,cat,fetcher=mock_commit)

    def test_upstream_source_and_regression_test_blob_checked(self):
        old,train,cat=inputs()
        def tamper(url):
            d=mock_commit(url)
            if url.endswith(old["cases"][0]["commit"]):
                d["files"][0]["sha"]="a"*40
            return d
        with self.assertRaises(RealFixError):
            generate(old,train,cat,fetcher=tamper)

    def test_upstream_single_parent_refused(self):
        old,train,cat=inputs()
        def forged_parent(url):
            d=mock_commit(url)
            if url.endswith(old["cases"][0]["commit"]):
                d["parents"]=[{"sha":"a"*40}]
            return d
        with self.assertRaises(RealFixError):
            generate(old,train,cat,fetcher=forged_parent)

    def test_missing_real_test_patch_refused(self):
        old,train,cat=inputs()
        def no_test(url):
            d=mock_commit(url)
            if url.endswith(old["cases"][0]["commit"]):
                d["files"].pop()
            return d
        with self.assertRaises(RealFixError):
            generate(old,train,cat,fetcher=no_test)

    def test_do_not_accept_unreviewed_catalog_promoted_to_labels(self):
        for key,value in (("independent_human_reviews",1),("network_eligible",True)):
            with self.subTest(key=key):
                old,train,cat=inputs()
                cat[key]=value
                with self.assertRaises(ProofError):
                    generate(old,train,cat,fetcher=mock_commit)

    def test_missing_source_or_source_family_rejected(self):
        old,train,cat=inputs()
        old["cases"].pop()
        with self.assertRaises(ProofError):
            generate(old,train,cat,fetcher=mock_commit)

    def test_unexpected_fresh_project_leakage_rejected(self):
        old,train,cat=inputs()
        old["cases"][0]["id"]="fresh-tornado-cookie-attribute"
        with self.assertRaises((ProofError,RealFixError)):
            generate(old,train,cat,fetcher=mock_commit)

    def test_pinned_original_cve_and_source_advisories_remain_upstream(self):
        d=generate(*inputs(),fetcher=mock_commit)
        for p in d["review_packets"]:
            self.assertTrue(p["cve"].startswith("CVE-"))
            self.assertTrue(p["advisory"].startswith("GHSA-"))
            self.assertTrue(p["source_url"].startswith("https://github.com/"))
            self.assertTrue(p["test_url"].startswith("https://github.com/"))
            self.assertNotIn("source_patch",p) # avoid copying full upstream source into output


if __name__=="__main__":
    unittest.main()
