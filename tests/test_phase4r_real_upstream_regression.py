"""Synthetic-only mutation tests for real upstream runtime proof validation."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase4r_real_upstream_regression as r
from falsum.phase4p_open_source_review import load_lock, git_blob_sha1

LOCK = Path(__file__).resolve().parents[1] / "data/phase4p-three-project-open-review-lock.json"
SOURCES = {
    "parent_source":b"original vulnerable upstream source\n",
    "fixed_source":b"fixed guarded source\n",
    "parent_test":b"original test file\n",
    "fixed_test":b"new upstream regression test\n",
}
LOGS = {
    "koa":{
        "parent-original":"should redirect to same origin Referer\npass 7\n",
        "parent-regression":"should fix Trailing Double-Slash security issue\nnot ok 1\nAssertionError: unequal\nactual: '//evil.com/login/'\n",
        "fixed-regression":"should fix Trailing Double-Slash security issue\npass 8\n",
    },
    "hono":{
        "parent-original":"src/middleware/csrf/index.test.ts\nTests 34 passed (34)\n",
        "parent-regression":"src/middleware/csrf/index.test.ts hyperlink auditing text/ping\nAssertionError: expected 200 to be 403\nTests 3 failed\n",
        "fixed-regression":"src/middleware/csrf/index.test.ts hyperlink auditing text/ping\nTests 4 passed\n",
    }
}


def setup(target:str,root:Path):
    case_id,stage_name,_=r.TARGETS[target]
    lock=copy.deepcopy(load_lock(LOCK.read_bytes()))
    row=next(x for x in lock["cases"] if x["id"]==case_id)
    stage=next(x for x in row["patches"] if x["stage"]==stage_name)
    stage["parent_source_blob"]=git_blob_sha1(SOURCES["parent_source"])
    stage["fixed_source_blob"]=git_blob_sha1(SOURCES["fixed_source"])
    stage["parent_test_blob"]=git_blob_sha1(SOURCES["parent_test"])
    stage["fixed_test_blob"]=git_blob_sha1(SOURCES["fixed_test"])
    parent=root/"parent";fixed=root/"fixed";logs=root/"logs"
    for path in (parent,fixed,logs):
        path.mkdir()
    for rootdir,key in ((parent,"parent_source"),(fixed,"fixed_source")):
        file=rootdir/stage["source_path"];file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(SOURCES[key])
    for rootdir in (parent,fixed):
        file=rootdir/stage["test_path"];file.parent.mkdir(parents=True,exist_ok=True)
        file.write_bytes(SOURCES["fixed_test"])
    for name,content in LOGS[target].items():
        (logs/(name+".log")).write_text(content)
        (logs/(name+".exit")).write_text("1" if name=="parent-regression" else "0")
    def git(wt,*args):
        if args==("rev-parse","HEAD"):
            return stage["parent"] if wt==parent else stage["fix"]
        if args==("cat-file","-p","HEAD"):
            return "tree "+("f"*40)+"\nparent "+stage["parent"]+"\nauthor synthetic <source@invalid.example>\n\nmessage"
        raise AssertionError("Unexpected git invocation: "+str(args))
    return lock,parent,fixed,logs,git,stage


class RealUpstreamEvidenceProofTests(unittest.TestCase):
    def test_accepts_predeclared_counterfactual_from_fake_logs_without_expert_labels(self):
        for target in r.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                lock,parent,fixed,logs,git,stage=setup(target,Path(d))
                with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                    data=r.inspect(LOCK.read_bytes(),target,parent,fixed,logs)
                self.assertEqual(data["status"],r.STATUS)
                self.assertTrue(data["real_upstream_runtime_tests_executed"])
                self.assertEqual(data["independent_human_appsec_labels"],0)
                self.assertFalse(data["original_model_improvement_proven"])
                self.assertFalse(data["network_evaluator_registered"])
                self.assertTrue(data["fixed_implementation_test_fails_on_parent"])
                self.assertTrue(data["exact_pinned_fixed_source_security_regression_passed"])
                self.assertEqual(data["exit_statuses"]["parent_with_fixed_security_regression"],1)
                self.assertEqual(data["upstream_source_and_test_provenance"]["fixed_source_commit"],stage["fix"])
                self.assertNotIn("secret",json.dumps(data).lower())
                self.assertNotIn("new upstream regression test",json.dumps(data))

    def test_parent_counterfactual_must_fail_and_original_test_must_pass(self):
        for target in r.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                lock,parent,fixed,logs,git,_=setup(target,Path(d))
                for name,value in (("parent-regression","0"),("parent-original","1"),
                                   ("fixed-regression","1")):
                    evidence=logs/(name+".exit");old=evidence.read_text();evidence.write_text(value)
                    with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                        with self.assertRaisesRegex(r.RuntimeEvidenceError,"parent baseline PASS"):
                            r.inspect(LOCK.read_bytes(),target,parent,fixed,logs)
                    evidence.write_text(old)

    def test_unrelated_failure_cannot_be_called_a_security_regression(self):
        for target in r.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                lock,parent,fixed,logs,git,_=setup(target,Path(d))
                (logs/"parent-regression.log").write_text(
                    "ModuleNotFoundError dependency unavailable, not a security failure")
                with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                    with self.assertRaisesRegex(r.RuntimeEvidenceError,"lacks named upstream security test"):
                        r.inspect(LOCK.read_bytes(),target,parent,fixed,logs)

    def test_wrong_actual_assertion_will_not_pass(self):
        for target in r.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                lock,parent,fixed,logs,git,_=setup(target,Path(d))
                name=r.TARGETS[target][2]
                (logs/"parent-regression.log").write_text(name+"\nFAIL: unrelated timeout, no true assertion")
                with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                    with self.assertRaises(r.RuntimeEvidenceError):
                        r.inspect(LOCK.read_bytes(),target,parent,fixed,logs)

    def test_modified_parent_or_fixed_source_byte_fails_even_if_logs_say_pass(self):
        for target in r.TARGETS:
            with self.subTest(target=target),tempfile.TemporaryDirectory() as d:
                lock,parent,fixed,logs,git,stage=setup(target,Path(d))
                for wt in (parent,fixed):
                    path=wt/stage["source_path"]
                    before=path.read_bytes();path.write_bytes(before+b"silently changed")
                    with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                        with self.assertRaisesRegex(r.RuntimeEvidenceError,"Git blob identity differs"):
                            r.inspect(LOCK.read_bytes(),target,parent,fixed,logs)
                    path.write_bytes(before)

    def test_original_unmodified_parent_test_cannot_pretend_to_be_fixed_overlay(self):
        with tempfile.TemporaryDirectory() as d:
            lock,parent,fixed,logs,git,stage=setup("koa",Path(d))
            (parent/stage["test_path"]).write_bytes(SOURCES["parent_test"])
            with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                with self.assertRaisesRegex(r.RuntimeEvidenceError,"regression test Git blob"):
                    r.inspect(LOCK.read_bytes(),"koa",parent,fixed,logs)

    def test_wrong_commit_head_or_unrelated_parent_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            lock,parent,fixed,logs,git,stage=setup("hono",Path(d))
            def wrong_git(wt,*args):
                if wt==fixed and args==("cat-file","-p","HEAD"):
                    return "tree "+("f"*40)+"\nparent "+("0"*40)+"\n\nwrong parent"
                return git(wt,*args)
            with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=wrong_git):
                with self.assertRaisesRegex(r.RuntimeEvidenceError,"exact direct parent"):
                    r.inspect(LOCK.read_bytes(),"hono",parent,fixed,logs)

    def test_forged_log_symlink_or_oversize_exit_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            lock,parent,fixed,logs,git,_=setup("koa",Path(d))
            path=logs/"parent-regression.exit"
            path.write_text("99999999999999999")
            with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                with self.assertRaisesRegex(r.RuntimeEvidenceError,"oversized runtime artifact"):
                    r.inspect(LOCK.read_bytes(),"koa",parent,fixed,logs)

    def test_disallowed_target_or_invalid_lock_fails(self):
        with tempfile.TemporaryDirectory() as d:
            lock,parent,fixed,logs,git,_=setup("koa",Path(d))
            with patch.object(r,"load_lock",return_value=lock),patch.object(r,"_git",side_effect=git):
                with self.assertRaisesRegex(r.RuntimeEvidenceError,"unapproved upstream runtime target"):
                    r.inspect(LOCK.read_bytes(),"some-other-repo",parent,fixed,logs)
            with self.assertRaises(Exception):
                r.inspect(b'{"not_the_source_lock":1}',"koa",parent,fixed,logs)

    def test_cli_refuses_clobbering_an_existing_report(self):
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)/"p";fixed=Path(d)/"f";logs=Path(d)/"l"
            for path in (parent,fixed,logs):
                path.mkdir()
            out=Path(d)/"report.json";out.write_text("no overwrite")
            with self.assertRaises(SystemExit):
                r.main(["--lock",str(LOCK),"--target","koa",
                        "--parent-dir",str(parent),"--fixed-dir",str(fixed),
                        "--logs",str(logs),"--out",str(out)])
            self.assertEqual(out.read_text(),"no overwrite")


if __name__=="__main__":
    unittest.main()
