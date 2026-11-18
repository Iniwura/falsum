"""Synthetic negatives for LangChain's two real historical security-fix stages."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase4s_langchain_upstream_runtime as s
from falsum.phase4p_open_source_review import load_lock, git_blob_sha1

LOCK=Path(__file__).resolve().parents[1]/"data/phase4p-three-project-open-review-lock.json"


def fake(stage_name:str, root:Path):
    src=copy.deepcopy(load_lock(LOCK.read_bytes()))
    patch=next(x for x in src["cases"][1]["patches"] if x["stage"]==s.STAGES[stage_name][0])
    orig_source=b"actual dummy parent Python source\n"
    fixed_source=b"actual dummy fixed Python source\n"
    orig_test=b"genuine old test code\n"
    fixed_test=b"new security regression test code\n"
    for k,v in [
        ("parent_source_blob",orig_source),("fixed_source_blob",fixed_source),
        ("parent_test_blob",orig_test),("fixed_test_blob",fixed_test)
    ]:
        patch[k]=git_blob_sha1(v)
    dirs={}
    for stage in ("parent","fixed","logs"):
        p=root/stage;p.mkdir();dirs[stage]=p
    for phase,contents in (("parent",orig_source),("fixed",fixed_source)):
        path=dirs[phase]/patch["source_path"]
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(contents)
        test=dirs[phase]/patch["test_path"]
        test.parent.mkdir(parents=True,exist_ok=True)
        test.write_bytes(fixed_test)
    logpath=dirs["logs"]
    expect=s.STAGES[stage_name][1]
    logs={
        "parent-original":"tests/unit_tests/prompts/test_loading.py::test_loading_from_yaml PASSED\n1 passed",
        "parent-new-regression":(
            "tests/unit_tests/prompts/test_loading.py::"+expect[0]+
            " FAILED\n"+"\n".join(expect)+"\nFailed: DID NOT RAISE <class 'ValueError'>\n"
        ),
        "fixed-new-regression":(
            "\n".join(f"tests/unit_tests/prompts/test_loading.py::{test} PASSED"
                      for test in expect)+"\n"+
            str(len(expect))+" passed"
        ),
    }
    for key,value in logs.items():
        (logpath/(key+".log")).write_text(value)
        (logpath/(key+".exit")).write_text("1" if key=="parent-new-regression" else "0")
    def mock_git(tree,*args):
        if args==("rev-parse","HEAD"):
            return patch["parent"] if tree==dirs["parent"] else patch["fix"]
        if args==("cat-file","-p","HEAD"):
            return "tree "+("a"*40)+"\nparent "+patch["parent"]+"\n\ncommit"
        raise AssertionError("unexpected raw git command")
    return src,dirs,mock_git,patch


class LangChainTwoStageRuntimeProofTests(unittest.TestCase):
    def test_unblinded_source_branch_negative_and_fixed_positive_both_stages(self):
        for key in s.STAGES:
            with self.subTest(stage=key),tempfile.TemporaryDirectory() as d:
                src,dirs,git,patch=fake(key,Path(d))
                with patch_loader(src,git):
                    report=s.verify(LOCK.read_bytes(),key,dirs["parent"],dirs["fixed"],dirs["logs"])
                self.assertEqual(report["status"],s.STATUS)
                self.assertTrue(report["real_original_upstream_python_tests_executed"])
                self.assertTrue(report["parent_failure_matched_missing_valueerror_not_dependency_error"])
                self.assertFalse(report["trained_evaluator_adapter"])
                self.assertFalse(report["real_deployed_file_access_proven"])
                self.assertEqual(report["independently_verified_expert_gold"],0)
                self.assertEqual(report["new_anjoman_eligible_rows"],0)
                self.assertTrue(report["test_did_not_exercise_jinja_code_execution_payload"])
                self.assertEqual(report["fixed_source_commit"],patch["fix"])
                self.assertEqual(len(report["selected_new_upstream_security_tests"]),
                                 len(s.STAGES[key][1]))

    def test_changed_statuses_fail_closed(self):
        for key in s.STAGES:
            with self.subTest(stage=key),tempfile.TemporaryDirectory() as d:
                src,dirs,git,_=fake(key,Path(d))
                for stem,new in (("parent-original","1"),
                                 ("parent-new-regression","0"),
                                 ("fixed-new-regression","1")):
                    path=dirs["logs"]/(stem+".exit");old=path.read_bytes()
                    path.write_text(new)
                    with patch_loader(src,git),self.assertRaisesRegex(
                            s.TwoStageEvidenceError,"original upstream control"):
                        s.verify(LOCK.read_bytes(),key,dirs["parent"],dirs["fixed"],dirs["logs"])
                    path.write_bytes(old)

    def test_unrelated_dependency_failure_not_a_true_negative(self):
        for key in s.STAGES:
            with self.subTest(stage=key),tempfile.TemporaryDirectory() as d:
                src,dirs,git,_=fake(key,Path(d))
                path=dirs["logs"]/"parent-new-regression.log"
                path.write_text("FAILED "+s.STAGES[key][1][0]+" ImportError: no module named pydantic")
                with patch_loader(src,git),self.assertRaisesRegex(
                        s.TwoStageEvidenceError,"missing-ValueError assertion"):
                    s.verify(LOCK.read_bytes(),key,dirs["parent"],dirs["fixed"],dirs["logs"])

    def test_forged_fix_source_and_regression_test_rejected(self):
        for key in s.STAGES:
            with self.subTest(stage=key),tempfile.TemporaryDirectory() as d:
                src,dirs,git,stage=fake(key,Path(d))
                for kind in ("source","test"):
                    path=dirs["fixed"]/stage[kind+"_path"]
                    old=path.read_bytes();path.write_bytes(old+b"malicious")
                    with patch_loader(src,git),self.assertRaisesRegex(
                            s.TwoStageEvidenceError,"blob mismatch"):
                        s.verify(LOCK.read_bytes(),key,dirs["parent"],dirs["fixed"],dirs["logs"])
                    path.write_bytes(old)

    def test_missing_fixed_specific_security_test_name_fails(self):
        with tempfile.TemporaryDirectory() as d:
            src,dirs,git,_=fake("initial",Path(d))
            path=dirs["logs"]/"fixed-new-regression.log"
            path.write_text("test_load_template_rejects_absolute_path PASSED\n1 passed")
            with patch_loader(src,git),self.assertRaisesRegex(
                    s.TwoStageEvidenceError,"exact upstream regression test absent"):
                s.verify(LOCK.read_bytes(),"initial",dirs["parent"],dirs["fixed"],dirs["logs"])

    def test_no_source_parent_forgery_using_raw_commit_headers(self):
        with tempfile.TemporaryDirectory() as d:
            src,dirs,git,_=fake("followup",Path(d))
            def corrupted(tree,*args):
                if args==("cat-file","-p","HEAD"):
                    return "tree "+("f"*40)+"\nparent "+("0"*40)+"\n\nfake"
                return git(tree,*args)
            with patch_loader(src,corrupted),self.assertRaisesRegex(
                    s.TwoStageEvidenceError,"direct-parent mismatch"):
                s.verify(LOCK.read_bytes(),"followup",dirs["parent"],dirs["fixed"],dirs["logs"])

    def test_wrong_source_lock_and_stage_refused(self):
        with tempfile.TemporaryDirectory() as d:
            src,dirs,git,_=fake("initial",Path(d))
            with patch_loader(src,git),self.assertRaisesRegex(
                    s.TwoStageEvidenceError,"unapproved stage"):
                s.verify(LOCK.read_bytes(),"unrelated",dirs["parent"],dirs["fixed"],dirs["logs"])
            with self.assertRaises(Exception):
                s.verify(b'{"forged":true}',"initial",dirs["parent"],dirs["fixed"],dirs["logs"])

    def test_report_refuses_overwrite_even_with_unchecked_worktree(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/"existing.json";out.write_text("untouched")
            with self.assertRaises(SystemExit):
                s.main(["--lock",str(LOCK),"--stage","initial",
                        "--parent",d,"--fixed",d,"--logs",d,"--out",str(out)])
            self.assertEqual(out.read_text(),"untouched")


def patch_loader(source,git):
    from contextlib import contextmanager
    @contextmanager
    def patched():
        with patch.object(s,"load_lock",return_value=source),patch.object(s,"git",side_effect=git):
            yield
    return patched()


if __name__=="__main__":
    unittest.main()
