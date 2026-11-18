"""Phase 4P synthetic source-metadata guards, never external expert/gold tests."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase4p_open_source_review as p

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "data/phase4p-three-project-open-review-lock.json"


def fake_commit(repo: str, stage: dict) -> dict:
    return {
        "sha": stage["fix"],
        "html_url": f"https://github.com/{repo}/commit/{stage['fix']}",
        "parents": [{"sha":stage["parent"]}],
        "files": [{
            "filename":stage["source_path"],"status":"modified",
            "sha":stage["fixed_source_blob"],"additions":4,"deletions":2,
            "patch":"@@ -1,2 +1,4 @@\n-old branch\n+new guarded branch\n+source unchanged elsewhere"
        },{
            "filename":stage["test_path"],"status":"modified",
            "sha":stage["fixed_test_blob"],"additions":4,"deletions":0,
            "patch":"@@ -2,2 +2,6 @@\n unchanged\n+regression test is added\n+tested input"
        }],
    }


class OpenSourceChallengeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = LOCK.read_bytes()
        cls.lock = p.load_lock(cls.raw)

    def test_immutable_prior_to_scoring_three_distinct_project_source_lock(self):
        manifest=self.lock
        self.assertEqual(p.git_blob_sha1(self.raw),p.LOCK_BLOB_SHA1)
        self.assertEqual(len(manifest["cases"]),3)
        self.assertEqual(tuple(row["id"] for row in manifest["cases"]),p.ID_ORDER)
        self.assertEqual(sum(len(row["patches"]) for row in manifest["cases"]),4)
        self.assertEqual(sum(len(row["questions"]) for row in manifest["cases"]),6)
        self.assertEqual(len({row["repository"] for row in manifest["cases"]}),3)
        self.assertTrue(manifest["no_answer_candidates_or_author_golden_verdicts"])
        self.assertTrue(manifest["not_a_sealed_or_model_pretraining_blind_holdout"])
        self.assertFalse(manifest["registered_evaluator"])

    def test_raw_git_file_blob_hashing_accepts_exact_bytes_only(self):
        value=b"public fake regression test text\n"
        expected=p.git_blob_sha1(value)
        checked=p.verify_blob(value,expected)
        self.assertEqual(checked["sha256"],p.digest(value))
        self.assertEqual(checked["bytes"],len(value))
        for changed in (value+b"\n",b"",b"public fake OTHER file\n"):
            with self.subTest(changed=changed):
                with self.assertRaises(p.NewReviewError):
                    p.verify_blob(changed,expected)
        with self.assertRaises(p.NewReviewError):
            p.verify_blob(b"x"*(p.MAX_RAW_FILE+1),p.git_blob_sha1(b"x"))

    def test_canonical_commit_parent_source_and_test_patches_accepted_only(self):
        for row in self.lock["cases"]:
            for stage in row["patches"]:
                a=p.check_commit(stage,row["repository"],
                                 fake_commit(row["repository"],stage))
                self.assertTrue(a["source"]["modified_in_same_upstream_commit"])
                self.assertTrue(a["test"]["modified_in_same_upstream_commit"])
                self.assertEqual(a["source"]["git_blob_sha1"],stage["fixed_source_blob"])

    def test_deletion_only_security_guard_removal_is_valid_source_change(self):
        row=self.lock["cases"][0]
        stage=row["patches"][0]
        obj=fake_commit(row["repository"],stage)
        obj["files"][0]["additions"]=0
        obj["files"][0]["deletions"]=6
        obj["files"][0]["patch"]="@@ -322,6 +322,0 @@\n-unsafe bypass branch\n-early return"
        info=p.check_commit(stage,row["repository"],obj)
        self.assertEqual(info["source"]["line_additions"],0)
        self.assertEqual(info["source"]["line_deletions"],6)

    def test_zero_change_source_or_test_is_rejected(self):
        row=self.lock["cases"][0]
        stage=row["patches"][0]
        for i in (0,1):
            obj=fake_commit(row["repository"],stage)
            obj["files"][i]["additions"]=0
            obj["files"][i]["deletions"]=0
            with self.subTest(index=i),self.assertRaisesRegex(
                    p.NewReviewError,"expected edited"):
                p.check_commit(stage,row["repository"],obj)

    def test_false_parent_cannot_pass_source_change_audit(self):
        row=self.lock["cases"][0]
        obj=fake_commit(row["repository"],row["patches"][0])
        obj["parents"][0]["sha"]="f"*40
        with self.assertRaisesRegex(p.NewReviewError,"parent"):
            p.check_commit(row["patches"][0],row["repository"],obj)

    def test_missing_regression_patch_cannot_be_claimed(self):
        row=self.lock["cases"][2]
        stage=row["patches"][0]
        obj=fake_commit(row["repository"],stage)
        obj["files"].pop()
        with self.assertRaisesRegex(p.NewReviewError,"test file"):
            p.check_commit(stage,row["repository"],obj)

    def test_forged_commit_sha_or_bad_source_blob_cannot_pass(self):
        row=self.lock["cases"][1]
        stage=row["patches"][0]
        obj=fake_commit(row["repository"],stage)
        obj["sha"]="0"*40
        with self.assertRaisesRegex(p.NewReviewError,"noncanonical"):
            p.check_commit(stage,row["repository"],obj)
        obj=fake_commit(row["repository"],stage)
        obj["files"][0]["sha"]="0"*40
        with self.assertRaisesRegex(p.NewReviewError,"edited source"):
            p.check_commit(stage,row["repository"],obj)

    def test_fake_test_file_without_real_patch_rejected(self):
        row=self.lock["cases"][2]
        stage=row["patches"][0]
        obj=fake_commit(row["repository"],stage)
        obj["files"][1]["patch"]="no actual diff"
        with self.assertRaisesRegex(p.NewReviewError,"patch"):
            p.check_commit(stage,row["repository"],obj)

    def test_locked_manifest_tamper_blocked_before_work_or_scoring(self):
        original=json.loads(self.raw)
        for changed in (
            lambda x:x["cases"][0].update(repository="psf/requests"),
            lambda x:x["cases"][1]["patches"][1].update(
                fixed_source_blob="0"*40),
            lambda x:x["cases"][0].update(questions=["A"]),
            lambda x:x.update(registered_evaluator=True),
            lambda x:x.update(no_expert_labels=False),
        ):
            data=copy.deepcopy(original)
            changed(data)
            with self.assertRaisesRegex(p.NewReviewError,"lock Git blob changed"):
                p.load_lock(json.dumps(data).encode())

    def test_source_disjoint_rule_still_applies_if_manifest_hash_updated(self):
        original=json.loads(self.raw)
        original["cases"][0]["repository"]="psf/requests"
        raw=json.dumps(original).encode()
        with patch.object(p,"LOCK_BLOB_SHA1",p.git_blob_sha1(raw)):
            with self.assertRaisesRegex(p.NewReviewError,"reused scored project"):
                p.load_lock(raw)

    def test_only_open_ended_questions_and_no_answers_can_be_introduced(self):
        doc=json.loads(self.raw)
        doc["cases"][0]["preferred_answer"]="A"
        raw=json.dumps(doc).encode()
        with patch.object(p,"LOCK_BLOB_SHA1",p.git_blob_sha1(raw)):
            with self.assertRaisesRegex(p.NewReviewError,"answer key"):
                p.load_lock(raw)

    def test_langchain_followup_git_blob_continuity_cannot_be_erased(self):
        doc=json.loads(self.raw)
        doc["cases"][1]["patches"][1]["parent_source_blob"]="e"*40
        raw=json.dumps(doc).encode()
        with patch.object(p,"LOCK_BLOB_SHA1",p.git_blob_sha1(raw)):
            with self.assertRaisesRegex(p.NewReviewError,"do not connect"):
                p.load_lock(raw)

    def test_safe_raw_url_rejects_traversal_before_network(self):
        with patch("falsum.phase4p_open_source_review.urllib.request.urlopen") as network:
            for path in ("../evil.py","a/../thing.py","a//b.py",
                         "https://attacker.example/x"):
                with self.subTest(path=path),self.assertRaises(p.NewReviewError):
                    p.raw_file("koajs/koa","a"*40,path)
            network.assert_not_called()

    def test_redirected_raw_source_rejected_without_accepting_untrusted_bytes(self):
        class BadRedirect:
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def geturl(self):return "https://attacker.example/source"
            def read(self,n):return b"attacker controlled source"
        with patch("falsum.phase4p_open_source_review.urllib.request.urlopen",
                   return_value=BadRedirect()):
            with self.assertRaisesRegex(p.NewReviewError,"redirected"):
                p.raw_file("koajs/koa","a"*40,"lib/response.js")

    def test_casebook_assembled_from_pinned_metadata_but_mock_blobs_are_not_real_evidence(self):
        index={
            row["patches"][i]["fix"]:
            fake_commit(row["repository"],row["patches"][i])
            for row in self.lock["cases"] for i in range(len(row["patches"]))
        }
        def fake_commit_fetch(url):
            return index[url.rsplit("/",1)[1]]
        # Deliberately MOCK each test/source blob verification. Only the real
        # GitHub Actions source-proving workflow counts as an upstream proof.
        with patch.object(p,"verify_blob",
                          side_effect=lambda raw,sha:{"git_blob_sha1":sha,"sha256":"MOCK_NOT_EXTERNAL","bytes":len(raw)}):
            result=p.generate(self.raw,commit_fetcher=fake_commit_fetch,
                              file_fetcher=lambda repo,rev,path:b"synthetic")
        self.assertEqual(result["distinct_new_upstream_projects"],3)
        self.assertEqual(result["commit_parent_paths_and_test_changes_verified"],4)
        self.assertEqual(result["raw_parent_and_fixed_source_and_test_blob_pairs_verified"],16)
        self.assertEqual(result["open_ended_review_questions"],6)
        self.assertEqual(result["expert_verified_reviewers"],0)
        self.assertFalse(result["actual_telegraph_foundation_inference"])
        self.assertFalse(result["ready_to_train_or_claim_model_improvement"])
        self.assertTrue(result["public_sources_are_not_independent_gold"])
        self.assertEqual(len(result["cases"][1]["verified_patch_stages"]),2)
        self.assertTrue(all(row["answer_key"] is None for row in result["cases"]))

    def test_full_verify_rejects_even_one_corrupt_raw_blob(self):
        index={stage["fix"]:fake_commit(row["repository"],stage)
               for row in self.lock["cases"] for stage in row["patches"]}
        with self.assertRaisesRegex(p.NewReviewError,"blob mismatch"):
            p.generate(self.raw,
                       commit_fetcher=lambda url:index[url.rsplit("/",1)[1]],
                       file_fetcher=lambda *_:b"not the pinned real source")

    def test_cli_never_overwrites_existing_output(self):
        with tempfile.TemporaryDirectory() as workdir:
            f=Path(workdir)/"present.json"
            f.write_text("safety record")
            with self.assertRaises(SystemExit):
                p.main(["--lock",str(LOCK),"--out",str(f)])
            self.assertEqual(f.read_text(),"safety record")


if __name__=="__main__":
    unittest.main()
