"""Phase 4S: real upstream LangChain initial and follow-up regression evidence.

Two *distinct* public security fixes (not consecutive history) must have:
old upstream original-control test PASS, fixed upstream security regression
FAIL at the exact direct parent for an actual missing ValueError, and PASS
on the fixed commit using exactly the same immutable new test source.

This is code-execution proof only. It does not create expert review labels,
model scores, a trained scorer or new Anjoman evaluation rows.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from .phase4p_open_source_review import load_lock, git_blob_sha1

STATUS = "PHASE4S_REAL_LANGCHAIN_TWO_STAGE_REGRESSIONS_NOT_HUMAN_GOLD"
STAGES = {
    "initial": ("initial-default-path-validation",
                ("test_load_template_rejects_absolute_path",
                 "test_load_template_rejects_traversal")),
    "followup": ("followup-resolved-symlink-suffix",
                 ("test_symlink_txt_to_py_is_blocked",)),
}
MAX_FILE = 160_000
MAX_LOG = 3_000_000


class TwoStageEvidenceError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise TwoStageEvidenceError(reason)


def read(path: Path, maximum: int) -> bytes:
    require(path.is_file() and not path.is_symlink(),
            "missing, symlinked or nonregular upstream evidence file")
    n = path.stat().st_size
    require(0 < n <= maximum, "missing or oversized actual upstream test evidence")
    return path.read_bytes()


def shas(raw: bytes) -> dict:
    return {"git_blob_sha1": git_blob_sha1(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}


def stage(lock: dict, key: str) -> tuple[dict, dict]:
    require(key in STAGES, "unapproved stage")
    rows = [r for r in lock["cases"] if r["id"] == "phase4p-langchain-prompt-path"]
    require(len(rows) == 1 and rows[0]["repository"] == "langchain-ai/langchain",
            "LangChain selected public source row missing")
    stages = [s for s in rows[0]["patches"] if s["stage"] == STAGES[key][0]]
    require(len(stages) == 1, "selected LangChain repair stage not in frozen source lock")
    return rows[0],stages[0]


def git(wt: Path, *args: str) -> str:
    require(wt.is_dir() and not wt.is_symlink(),
            "upstream checkout must be a normal directory")
    try:
        completed=subprocess.run(["git","-C",str(wt),*args],
              text=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
              check=True,timeout=8)
        return completed.stdout.strip()
    except (OSError,subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        raise TwoStageEvidenceError("unable to validate exact upstream Git object") from exc


def verify_tree(stage: dict, directory: Path, revision: str,
                overlaid_new_test: bool) -> dict:
    require(revision in ("parent","fixed"), "unapproved code revision")
    commit = stage["parent"] if revision == "parent" else stage["fix"]
    require(git(directory,"rev-parse","HEAD") == commit, "executed Git commit mismatch")
    if revision=="fixed":
        raw=git(directory,"cat-file","-p","HEAD")
        hdr=raw.split("\n\n",1)[0].splitlines()
        parents=[line[7:] for line in hdr if line.startswith("parent ")]
        require(parents == [stage["parent"]], "raw fixed Git commit direct-parent mismatch")
    source = read(directory/stage["source_path"],MAX_FILE)
    test = read(directory/stage["test_path"],MAX_FILE)
    expected_test_sha = (stage["fixed_test_blob"] if overlaid_new_test
                         else stage[f"{revision}_test_blob"])
    require(git_blob_sha1(source)==stage[f"{revision}_source_blob"],
            "loaded LangChain implementation does not match frozen Git blob")
    require(git_blob_sha1(test)==expected_test_sha,
            "executed original or overlaid LangChain regression test blob mismatch")
    return {
        "exact_checkout":commit,
        "original_source":shas(source),
        "executed_upstream_test":shas(test),
        "parent_regression_test_overlaid_only":overlaid_new_test,
    }


def _status(log_dir: Path, stem: str) -> int:
    value = read(log_dir/(stem+".exit"),10).decode("ascii",errors="strict").strip()
    require(re.fullmatch(r"[0-9]{1,3}",value) is not None, "test process status not an exit code")
    number=int(value)
    require(0<=number<=255, "test process status outside OS exit range")
    return number


def _log(log_dir:Path, stem:str)->tuple[str,str]:
    data=read(log_dir/(stem+".log"),MAX_LOG)
    return data.decode("utf-8",errors="replace"),hashlib.sha256(data).hexdigest()


def verify(lock_bytes:bytes, key:str, parent_dir:Path,
           fixed_dir:Path,log_dir:Path)->dict:
    frozen=load_lock(lock_bytes)
    row,s=stage(frozen,key)
    require(parent_dir.resolve()!=fixed_dir.resolve(),"cannot execute same code as before and after")
    orig=verify_tree(s,parent_dir,"parent",True)
    repaired=verify_tree(s,fixed_dir,"fixed",False)
    names=("parent-original","parent-new-regression","fixed-new-regression")
    codes={n:_status(log_dir,n) for n in names}
    require(codes["parent-original"]==0 and
            codes["parent-new-regression"]!=0 and
            codes["fixed-new-regression"]==0,
            "original upstream control must PASS; new security test must FAIL old and PASS fixed")
    raw={n:_log(log_dir,n) for n in names}
    expected=STAGES[key][1]
    require("test_loading_from_yaml" in raw["parent-original"][0],
            "old legitimate LangChain file-loading control not actually executed")
    require("1 passed" in raw["parent-original"][0].lower(),
            "original upstream control did not report a positive passed test")
    negative=raw["parent-new-regression"][0]
    good=raw["fixed-new-regression"][0]
    require("did not raise" in negative.casefold() and "valueerror" in negative.casefold(),
            "unfixed branch did not produce expected missing-ValueError assertion")
    for test in expected:
        require(test in negative and test in good,
                "expected exact upstream regression test absent from original/fixed execution")
    require("passed" in good.lower()
            and "failed" not in good.lower()
            and "error" not in good.lower(),
            "fixed stage test log lacks clear pass or contains a failure")
    return {
        "schema_version":1,
        "status":STATUS,
        "repair_stage":key,
        "project":"langchain-ai/langchain",
        "source_case":row["id"],
        "original_source_commit":s["parent"],
        "fixed_source_commit":s["fix"],
        "actual_upstream_source_and_test_byte_identities":{
            "parent_with_new_regression":orig,
            "fixed_with_new_regression":repaired,
        },
        "original_upstream_control_test":"test_loading_from_yaml",
        "selected_new_upstream_security_tests":list(expected),
        "new_security_test_not_passing_old":True,
        "new_security_test_passing_fixed":True,
        "original_functionality_control_passed":True,
        "parent_failure_matched_missing_valueerror_not_dependency_error":True,
        "exit_statuses":codes,
        "logs_sha256":{n:raw[n][1] for n in names},
        "real_original_upstream_python_tests_executed":True,
        "one_security_patch_not_assumed_complete_without_followup":True,
        "public_unblinded_source_test_only":True,
        "test_did_not_exercise_jinja_code_execution_payload":True,
        "independently_verified_expert_gold":0,
        "new_anjoman_eligible_rows":0,
        "trained_evaluator_adapter":False,
        "improved_model_performance_proven":False,
        "real_deployed_file_access_proven":False,
        "message":(
          "Genuine upstream Pytest regression tests passed on the pinned fix "
          "and failed on the direct vulnerable Git parent for a missing "
          "ValueError while an original legitimate loading control passed. "
          "This is an executable source test, not a human gold label, "
          "production exploit, or improved trained evaluator."
        ),
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Authenticate two real LangChain fixed/parent Pytest runs")
    parser.add_argument("--lock",type=Path,required=True)
    parser.add_argument("--stage",choices=tuple(STAGES),required=True)
    parser.add_argument("--parent",type=Path,required=True)
    parser.add_argument("--fixed",type=Path,required=True)
    parser.add_argument("--logs",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        require(args.out.resolve()!=args.lock.resolve()
                and not args.out.exists() and not args.out.is_symlink(),
                "refuse overwriting proof or source lock")
        report=verify(read(args.lock,25_000),args.stage,args.parent,args.fixed,args.logs)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.out,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            json.dump(report,out,indent=2,sort_keys=True)
            out.write("\n")
        print(json.dumps({
            "stage":report["repair_stage"],
            "status":report["status"],
            "actual_upstream_parent_test_failed_expected":True,
            "actual_upstream_fixed_regression_passed":True,
            "independent_appsec_gold_labels":0,
            "model_improvement":False,
        },indent=2))
        return 0
    except (ValueError,OSError,KeyError,TypeError,UnicodeError,IndexError) as e:
        parser.exit(1,"FALSUM LANGCHAIN REAL PATCH TEST REFUSED: "+str(e)[:195]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
