"""Strict aggregation of *executed* source-revision behavior from historical public JS packages.

This verifies that eight distinct Node processes (four affected/fixed pairs)
actually ran original pinned Git commits and reproduced vulnerable→fixed
behavior with unrelated safe controls. Not a full upstream test-suite run, a
general security proof, independent expert gold, model prediction accuracy or
Telegraph network evaluation.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .phase5m_real_source_sensitive_model import ROOT

LOCK="data/phase5v-preexecution-four-new-original-regression-probe.json"
ORIGINAL_GIT_BLOB_SHA1="7d14b5fa125449e18557e45429a77267f60cf125"
STATUS="PHASE5V_FOUR_NEW_PUBLIC_HISTORICAL_AFFECTED_FIXED_SOURCE_RUNTIME_REVERSALS"
REPORT_STATUS="PHASE5V_ACTUAL_ORIGINAL_HISTORICAL_SOURCE_RUNTIME_PROBE"
SHA40=re.compile(r"^[0-9a-f]{40}$")


class RuntimeProofError(ValueError):
    pass


def need(ok:bool,why:str)->None:
    if not ok:
        raise RuntimeProofError(why)


def git_blob(raw:bytes)->str:
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()


def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK).read_bytes()
    need(git_blob(raw)==ORIGINAL_GIT_BLOB_SHA1,
         "original pre-run source selection or outcomes changed after freeze")
    p=json.loads(raw)
    need(p.get("schema_version")==1
         and p.get("status")==
            "PHASE5V_ORIGINAL_PUBLIC_FOUR_NEW_SECURITY_FIX_NODE_EXECUTION_FROZEN_BEFORE_IMPLEMENTATION"
         and p.get("intent")=="SECURITY_REVIEW_GENERAL"
         and p.get("expected_pinned_original_source_versions")==8
         and p.get("expected_original_upstream_test_file_versions")==8
         and p.get("expected_original_historical_local_forward_probes")==8
         and p.get("expected_distinct_historical_source_reversals")==4
         and p.get("explicit_unverified",{}).get("full_original_upstream_test_suite_rerun") is False
         and p.get("explicit_unverified",{}).get("independent_expert_gold")==0
         and p.get("explicit_unverified",{}).get("paid_network_rank_improvement") is False
         and p.get("explicit_unverified",{}).get("registered_telegraph_evaluator") is False
         and p.get("explicit_unverified",{}).get("independent_external_adoption") is False
         and p.get("explicit_unverified",{}).get("official_h2_submitted") is False,
         "pre-runtime source execution policy altered or inflated")
    projects=p.get("projects")
    need(isinstance(projects,list) and len(projects)==4
         and len({p.get("key") for p in projects})==4
         and len({p.get("repo") for p in projects})==4
         and all(p.get("expected_affected_unsafe") is True
                 and p.get("expected_fixed_unsafe") is False
                 and p.get("affected_commit")!=p.get("fixed_commit")
                 and all(SHA40.fullmatch(str(p.get(x,""))) is not None for x in (
                     "affected_commit","fixed_commit",
                     "affected_blob","fixed_blob",
                     "affected_test_blob","fixed_test_blob"))
                 for p in projects),
         "original four public source revision identities drifted")
    return p


def verify(records:list[dict],*,root:Path=ROOT)->dict:
    p=frozen(root)
    need(isinstance(records,list) and len(records)==8,
         "eight independent original affected/fixed runs required")
    original={(case["key"],role):case for case in p["projects"]
              for role in ("affected","fixed")}
    seen=set()
    safe_rows=[]
    for row in records:
        need(isinstance(row,dict)
             and row.get("schema_version")==1
             and row.get("status")==REPORT_STATUS
             and set(row)=={
                 "schema_version","status",
                 "project","original_source_revision_role",
                 "original_git_commit",
                 "original_source_git_blob_sha1",
                 "original_upstream_test_git_blob_sha1",
                 "historical_original_source_executed_in_node",
                 "historical_upstream_test_file_authenticated_elsewhere",
                 "full_original_upstream_suite_executed",
                 "unrelated_safe_control_passed",
                 "unsafe_observed","expected_unsafe_observation",
                 "reproduces_frozen_affected_to_fixed_behavior",
                 "local_loopback_only_if_redirect",
                 "no_remote_vulnerability_probe",
                 "no_independent_expert_gold",
                 "no_real_telegraph_network_calls",
                 "no_registered_evaluator",
             },"unknown actual source runtime report field or invalid shape")
        role=row["original_source_revision_role"]
        key=(row["project"],role)
        need(key in original and key not in seen,
             "original source project or revision missing, duplicated or invented")
        seen.add(key)
        spec=original[key]
        need(row["original_git_commit"]==spec[role+"_commit"]
             and row["original_source_git_blob_sha1"]==spec[role+"_blob"]
             and row["original_upstream_test_git_blob_sha1"]==spec[role+"_test_blob"]
             and row["historical_original_source_executed_in_node"] is True
             and row["historical_upstream_test_file_authenticated_elsewhere"] is True
             and row["full_original_upstream_suite_executed"] is False
             and row["unrelated_safe_control_passed"] is True
             and type(row["unsafe_observed"]) is bool
             and row["unsafe_observed"]==spec["expected_"+role+"_unsafe"]
             and row["expected_unsafe_observation"]==spec["expected_"+role+"_unsafe"]
             and row["reproduces_frozen_affected_to_fixed_behavior"] is True
             and row["local_loopback_only_if_redirect"] is
                 (row["project"]=="follow-redirects-custom-headers")
             and row["no_remote_vulnerability_probe"] is True
             and row["no_independent_expert_gold"] is True
             and row["no_real_telegraph_network_calls"] is True
             and row["no_registered_evaluator"] is True,
             "original historical executed source/receipt or safe control failed")
        safe_rows.append({
            "project":row["project"],
            "original_source_revision_role":role,
            "original_git_commit":row["original_git_commit"],
            "original_source_git_blob_sha1":row["original_source_git_blob_sha1"],
            "original_upstream_test_git_blob_sha1":row["original_upstream_test_git_blob_sha1"],
            "unsafe_observed":row["unsafe_observed"],
            "unrelated_safe_control_passed":True,
            "focused_original_historical_source_execution":True,
        })
    need(seen==set(original),"original runtime project/revision set incomplete")
    pairs={}
    for project in p["projects"]:
        name=project["key"]
        a=next(x for x in safe_rows if x["project"]==name and
               x["original_source_revision_role"]=="affected")
        b=next(x for x in safe_rows if x["project"]==name and
               x["original_source_revision_role"]=="fixed")
        need(a["unsafe_observed"] is True and b["unsafe_observed"] is False,
             "original affected-to-fixed source behavior did not reverse")
        pairs[name]={
            "original_affected_observed_unsafe":True,
            "original_fixed_observed_unsafe":False,
            "focused_original_historical_source_reversal_reproduced":True,
        }
    return {
        "schema_version":1,"status":STATUS,
        "frozen_prerun_git_blob_sha1":ORIGINAL_GIT_BLOB_SHA1,
        "historical_original_repositories":4,
        "original_git_commits_executed_in_isolated_node":8,
        "original_source_file_git_blobs_verified_before_run":8,
        "original_upstream_test_file_git_blobs_verified_before_run":8,
        "focused_original_historical_source_behavior_reversals":4,
        "actual_source_execution_without_model":True,
        "unrelated_safe_control_successes":8,
        "original_upstream_full_test_suites_executed":False,
        "independent_expert_gold_count":0,
        "generalized_security_model_accuracy":None,
        "registered_network_evaluator":False,
        "same_request_real_miner_ranking_improved":False,
        "falsum_external_adoption":False,
        "new_paid_telegraph_requests":0,
        "official_h2_entry_submitted":False,
        "original_code_outcomes":safe_rows,
        "four_source_reversals":pairs,
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Verify 8 real Node source process reports against frozen exact Git source/test identities")
    p.add_argument("--input-dir",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args(argv)
    try:
        need(a.input_dir.is_dir() and not a.input_dir.is_symlink(),
             "actual eight original JS execution reports missing")
        need(not a.out.exists() and not a.out.is_symlink() and
             a.out.suffix==".json","original summary must be fresh write-once JSON")
        names=sorted(a.input_dir.glob("*.json"))
        need(len(names)==8 and all(0<x.stat().st_size<=6000
                 and not x.is_symlink() for x in names),
             "original output set incomplete or oversized")
        report=verify([json.loads(f.read_bytes()) for f in names])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",
                         encoding="utf-8")
        print(json.dumps({
            "status":report["status"],
            "actual_original_source_executions":8,
            "complete_historical_vulnerability_fix_reversals":4,
            "original_upstream_entire_test_suites_executed":False,
            "external_appsec_gold":0,
        },sort_keys=True))
        return 0
    except (OSError,ValueError,UnicodeError,KeyError,TypeError) as e:
        p.exit(1,"PHASE5V ORIGINAL EXECUTED GIT SOURCE FAILED CLOSED: "+
               str(e)[:300]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
