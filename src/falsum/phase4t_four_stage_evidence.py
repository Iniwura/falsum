"""Phase 4T: verify four genuine public upstream test executions in ONE index.

Input: authentic GitHub Actions run metadata and immutable artifact downloads,
plus the Phase 4P source lock.  Every claimed result must correspond to the
actual historical upstream parent/fix source and exact test-file Git blobs.

This is a *test-result provenance index*, not a human expert gold benchmark,
learned security evaluator, live application vulnerability proof, new Anjoman
submission, network adapter, or statistical model improvement.

Data artifacts are emitted once and never overwritten.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from .phase4p_open_source_review import load_lock

STATUS = "PHASE4T_FOUR_EXECUTED_UPSTREAM_SECURITY_REGRESSIONS_VERIFIED_NOT_MODEL_GOLD"
MANIFEST_STATUS = "PHASE4T_FOUR_PUBLIC_UPSTREAM_RUN_RECEIPTS_PINNED_2026_11_18"
PHASE4R_STATUS = "PHASE4R_REAL_UPSTREAM_PARENT_FAIL_FIX_PASS_TEST_EXECUTION_NOT_MODEL_GOLD"
PHASE4S_STATUS = "PHASE4S_REAL_LANGCHAIN_TWO_STAGE_REGRESSIONS_NOT_HUMAN_GOLD"
EXPECTED_IDS = (
    "koa-redirect","hono-csrf","langchain-path","langchain-symlink"
)
EXPECTED_RUNS = {"phase4r":44352329150, "phase4s":44353999011}
MAX_BYTES = 40_000
SHA40 = re.compile(r"^[a-f0-9]{40}$")
SHA64 = re.compile(r"^[a-f0-9]{64}$")


class ProvenanceError(ValueError):
    """A proposed public runtime result must not be promoted to proof."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProvenanceError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(path: Path, maximum: int = MAX_BYTES) -> bytes:
    require(path.is_file() and not path.is_symlink(),
            "source or public runtime record missing or symlinked")
    size = path.stat().st_size
    require(0 < size <= maximum, "public record empty or oversized")
    return path.read_bytes()


def json_object(raw: bytes, expected_type: str) -> dict:
    try:
        obj = json.loads(raw)
    except (ValueError,UnicodeError) as exc:
        raise ProvenanceError("invalid JSON for "+expected_type) from exc
    require(isinstance(obj,dict), expected_type+" must be JSON object")
    return obj


def validate_manifest(raw: bytes) -> dict:
    manifest=json_object(raw,"Phase 4T frozen index")
    require(set(manifest) == {
        "schema_version","status","source_lock","competition_intent",
        "contributor_status_is_separate_from_runtime_proof",
        "not_new_network_evaluation_material","no_human_expert_gold_labels",
        "not_a_model_accuracy_or_scoring_adapter_proof","runs","receipts"
    }, "Phase 4T immutable manifest schema drift")
    require(manifest["schema_version"]==1
            and manifest["status"]==MANIFEST_STATUS
            and manifest["source_lock"]=="data/phase4p-three-project-open-review-lock.json"
            and manifest["competition_intent"]=="SECURITY_REVIEW_GENERAL"
            and all(manifest[k] is True for k in (
                "contributor_status_is_separate_from_runtime_proof",
                "not_new_network_evaluation_material","no_human_expert_gold_labels",
                "not_a_model_accuracy_or_scoring_adapter_proof")),
            "source regression provenance cannot be promoted to network evaluation quality")
    runs=manifest["runs"]
    require(isinstance(runs,dict) and set(runs)==set(EXPECTED_RUNS),
            "unexpected GitHub source-workflow receipts")
    for key,run in runs.items():
        require(set(run)=={"id","head_sha","path","name","event"}
                and type(run["id"]) is int and run["id"]==EXPECTED_RUNS[key]
                and isinstance(run["head_sha"],str)
                and SHA40.fullmatch(run["head_sha"]) is not None
                and run["path"]==
                (".github/workflows/phase4r-real-upstream-regression.yml"
                 if key=="phase4r" else
                 ".github/workflows/phase4s-langchain-two-stage-runtime.yml")
                and run["event"]=="pull_request",
                "workflows must be pinned to original public PR run IDs and SHAs")
    entries=manifest["receipts"]
    require(isinstance(entries,list) and len(entries)==4
            and tuple(x.get("id") for x in entries)==EXPECTED_IDS,
            "four unique predeclared source-executed security cases required")
    for e in entries:
        require(set(e)=={"id","source_case","patch_stage","kind","target",
                         "run","artifact_name","file"}
                and e["kind"]==e["run"] and e["run"] in runs
                and isinstance(e["file"],str) and
                re.fullmatch(r"phase4[rs]-[a-z0-9-]+\.json",e["file"]) is not None
                and isinstance(e["artifact_name"],str) and
                re.fullmatch(r"phase4[rs]-[a-z0-9-]+",e["artifact_name"]) is not None,
                "unapproved runtime source receipt or artifact")
    require([x["target"] for x in entries]==["koa","hono","initial","followup"]
            and [x["run"] for x in entries]==[
                "phase4r","phase4r","phase4s","phase4s"],
            "expected four real project/stage execution targets changed")
    return manifest


def verify_run(run: dict, run_meta: dict) -> dict:
    require(isinstance(run_meta,dict), "no authenticated source run metadata")
    require(type(run_meta.get("databaseId")) is int
            and run_meta["databaseId"]==run["id"]
            and run_meta.get("headSha")==run["head_sha"]
            and run_meta.get("status")=="completed"
            and run_meta.get("conclusion")=="success"
            and run_meta.get("event")==run["event"]
            and run_meta.get("workflowName")==run["name"]
            and run_meta.get("url")==
            f"https://github.com/Iniwura/falsum/actions/runs/{run['id']}",
            "source GitHub run not a successful verified pinned workflow")
    return {
        "run_id":run["id"],"head_sha":run["head_sha"],"workflow":run["path"],
        "successful_public_run_url":run_meta["url"],
        "source_workflow_completed":True,
    }


def stage_lookup(lock: dict, entry: dict) -> tuple[dict,dict]:
    match=[r for r in lock["cases"] if r["id"]==entry["source_case"]]
    require(len(match)==1, "unknown public source provenance")
    row=match[0]
    stages=[s for s in row["patches"] if s["stage"]==entry["patch_stage"]]
    require(len(stages)==1, "missing exact frozen historical source/test stage")
    return row,stages[0]


def require_shas(receipt: dict) -> None:
    require(isinstance(receipt,dict),"missing runtime evidence receipt")
    require(any(k in receipt for k in ("raw_log_sha256","logs_sha256")),
            "missing actual upstream process-log SHA witnesses")
    keys=receipt.get("raw_log_sha256",receipt.get("logs_sha256"))
    require(isinstance(keys,dict) and len(keys)==3 and
            all(isinstance(v,str) and SHA64.fullmatch(v) is not None
                for v in keys.values()),
            "bad or missing three authentic process log hashes")


def verify_receipt(row:dict,stage:dict,entry:dict,receipt:dict)->dict:
    require_shas(receipt)
    kind=entry["kind"]
    require(receipt.get("schema_version")==1,
            "unrecognized upstream runtime receipt version")
    if kind=="phase4r":
        require(receipt.get("status")==PHASE4R_STATUS
                and receipt.get("target")==entry["target"]
                and receipt.get("upstream_repository")==row["repository"]
                and receipt.get("security_family")==row["security_family"]
                and receipt.get("baseline_upstream_parent_tests_passed") is True
                and receipt.get("fixed_implementation_test_fails_on_parent") is True
                and receipt.get("exact_pinned_fixed_source_security_regression_passed") is True
                and receipt.get("real_upstream_runtime_tests_executed") is True
                and receipt.get("regression_is_from_fixed_commit_not_a_homebrew_answer_key") is True
                and receipt.get("independent_human_appsec_labels")==0
                and receipt.get("new_anjoman_evaluation_rows")==0
                and receipt.get("original_model_improvement_proven") is False
                and receipt.get("network_evaluator_registered") is False
                and receipt.get("official_judge_certification") is False,
                "Phase 4R source/quality/negative controls not met")
        statuses=receipt.get("exit_statuses",{})
        require(isinstance(statuses,dict)
                and type(statuses.get("parent_original_upstream_tests")) is int
                and statuses["parent_original_upstream_tests"]==0
                and type(statuses.get("parent_with_fixed_security_regression")) is int
                and 1 <= statuses["parent_with_fixed_security_regression"]<=255
                and type(statuses.get("fixed_with_security_regression")) is int
                and statuses["fixed_with_security_regression"]==0,
                "real phase 4R parent-fail fixed-pass process results not demonstrated")
        p=receipt.get("upstream_source_and_test_provenance",{})
        require(p.get("parent_original_source_commit")==stage["parent"]
                and p.get("fixed_source_commit")==stage["fix"],
                "wrong parent or fixed public source commit")
        original=p.get("parent_with_fixed_regression_overlay",{})
        fixed=p.get("fixed_original_test",{})
        require(original.get("git_identity_checked") is True
                and fixed.get("git_identity_checked") is True
                and original.get("commit_sha")==stage["parent"]
                and fixed.get("commit_sha")==stage["fix"]
                and original.get("source_blob_sha1")==stage["parent_source_blob"]
                and original.get("executed_test_blob_sha1")==stage["fixed_test_blob"]
                and original.get("test_was_copied_from_pinned_fixed_upstream") is True
                and fixed.get("source_blob_sha1")==stage["fixed_source_blob"]
                and fixed.get("executed_test_blob_sha1")==stage["fixed_test_blob"]
                and fixed.get("test_was_copied_from_pinned_fixed_upstream") is False,
                "source or exact upstream test identity changed under counterfactual")
    else:
        require(receipt.get("status")==PHASE4S_STATUS
                and receipt.get("repair_stage")==entry["target"]
                and receipt.get("project")==row["repository"]
                and receipt.get("source_case")==row["id"]
                and receipt.get("original_source_commit")==stage["parent"]
                and receipt.get("fixed_source_commit")==stage["fix"]
                and receipt.get("real_original_upstream_python_tests_executed") is True
                and receipt.get("new_security_test_not_passing_old") is True
                and receipt.get("new_security_test_passing_fixed") is True
                and receipt.get("original_functionality_control_passed") is True
                and receipt.get("parent_failure_matched_missing_valueerror_not_dependency_error") is True
                and receipt.get("one_security_patch_not_assumed_complete_without_followup") is True
                and receipt.get("independently_verified_expert_gold")==0
                and receipt.get("new_anjoman_eligible_rows")==0
                and receipt.get("trained_evaluator_adapter") is False
                and receipt.get("improved_model_performance_proven") is False
                and receipt.get("real_deployed_file_access_proven") is False,
                "Phase 4S source/quality/negative controls not met")
        statuses=receipt.get("exit_statuses",{})
        require(isinstance(statuses,dict)
                and type(statuses.get("parent-original")) is int
                and statuses["parent-original"]==0
                and type(statuses.get("parent-new-regression")) is int
                and 1<=statuses["parent-new-regression"]<=255
                and type(statuses.get("fixed-new-regression")) is int
                and statuses["fixed-new-regression"]==0,
                "Phase 4S original/parent/fixed Pytest process evidence missing")
        prov=receipt.get("actual_upstream_source_and_test_byte_identities",{})
        for version,key in (("parent","parent_with_new_regression"),
                            ("fixed","fixed_with_new_regression")):
            obj=prov.get(key,{})
            expected_commit=stage["parent"] if version=="parent" else stage["fix"]
            require(obj.get("exact_checkout")==expected_commit
                    and obj.get("parent_regression_test_overlaid_only") is (version=="parent")
                    and obj.get("original_source",{}).get("git_blob_sha1")==
                    stage[f"{version}_source_blob"]
                    and obj.get("executed_upstream_test",{}).get("git_blob_sha1")==
                    stage["fixed_test_blob"],
                    "LangChain exact loaded Python source and test Git blob wrong")
    return {
        "case_id":entry["id"],
        "source_case":row["id"],
        "upstream_repository":row["repository"],
        "security_family":row["security_family"],
        "fix_stage":stage["stage"],
        "original_git_sha":stage["parent"],
        "fixed_git_sha":stage["fix"],
        "original_source_blob":stage["parent_source_blob"],
        "fixed_source_blob":stage["fixed_source_blob"],
        "fixed_regression_test_blob":stage["fixed_test_blob"],
        "original_upstream_tests_passed":True,
        "new_fixed_source_regression_failed_against_original_code":True,
        "same_regression_passed_against_fixed_code":True,
        "actual_upstream_code_executed":True,
        "independent_expert_gold_labels":0,
        "trained_model_or_evaluator_improvement_proven":False,
        "not_a_sealed_blind_holdout":True,
    }


def aggregate(lock_raw:bytes,manifest_raw:bytes,
              metas:dict[str,dict],receipts:dict[str,bytes])->dict:
    lock=load_lock(lock_raw)
    manifest=validate_manifest(manifest_raw)
    require(isinstance(metas,dict) and set(metas)==set(EXPECTED_RUNS),
            "must inspect BOTH original GitHub successful run identities")
    verified_runs={key:verify_run(run,metas[key])
                   for key,run in manifest["runs"].items()}
    require(isinstance(receipts,dict) and set(receipts)==set(EXPECTED_IDS),
            "missing, duplicate or extraneous upstream test proof")
    output=[]
    for entry in manifest["receipts"]:
        row,stage=stage_lookup(lock,entry)
        raw=receipts[entry["id"]]
        require(isinstance(raw,bytes) and 0<len(raw)<=MAX_BYTES,
                "invalid, oversized or missing actual upstream runtime evidence")
        evidence=json_object(raw,"public executed upstream test receipt")
        item=verify_receipt(row,stage,entry,evidence)
        item["source_receipt_sha256"]=sha(raw)
        item["public_actions_run"]=verified_runs[entry["run"]]["successful_public_run_url"]
        item["source_code_regression_artifact"]=entry["artifact_name"]
        output.append(item)
    require(len({(e["upstream_repository"],e["fix_stage"]) for e in output})==4,
            "four unique source/patch pairs not present")
    require(len({e["upstream_repository"] for e in output})==3,
            "exactly three upstream projects must be validated")
    # This is not four independent models, reviewers or projects. Two
    # LangChain stages are related work in the same repository.
    return {
        "schema_version":1,
        "status":STATUS,
        "intent_id":"SECURITY_REVIEW_GENERAL",
        "source_selection_sha256":sha(lock_raw),
        "proof_index_sha256":sha(manifest_raw),
        "two_verified_public_github_workflow_runs":verified_runs,
        "distinct_upstream_repositories":3,
        "historical_distinct_fixed_commit_stages":4,
        "actual_upstream_original_pass_parent_new_test_fail_fixed_new_test_pass":4,
        "source_grounded_open_review_questions":6,
        "original_upstream_test_and_source_git_identities_verifiable":True,
        "phase4o_author_written_a_b_material_promotion_allowed":False,
        "independent_human_appsec_gold_labels":0,
        "new_anjo_network_evaluation_rows":0,
        "live_network_evaluator_registered":False,
        "trained_model_improvement_proven":False,
        "production_exploitability_or_browser_attack_proven":False,
        "public_source_test_evidence_is_not_a_sealed_model_holdout":True,
        "official_hackathon_submission_confirmed":False,
        "receipts":output,
        "interpretation":(
            "Four distinct publicly reproducible real upstream regressions "
            "within three previously unscored public projects. Each checks original "
            "suite PASS; exact newer upstream security test FAIL on original source; "
            "same newer test PASS on fixed commit, with actual Git+blob and process "
            "log identities preserved. These are source-test coverage witnesses "
            "only, NOT model quality, expert gold, Anjoman eligibility, live "
            "attack validation or official hackathon acceptance."
        ),
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Verify 4 real GitHub Actions upstream source-test receipts")
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--runs-dir",type=Path,required=True)
    p.add_argument("--receipts-dir",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        require(args.out.resolve() not in {
            args.lock.resolve(),args.manifest.resolve()
        } and not args.out.exists() and not args.out.is_symlink(),
                "refuse overwrite or source/proof alias")
        lock=read(args.lock);manifest=read(args.manifest)
        fixed=validate_manifest(manifest)
        metas={key:json_object(read(args.runs_dir/(key+".json")),"GitHub run metadata")
               for key in EXPECTED_RUNS}
        receipts={r["id"]:read(args.receipts_dir/r["id"]/r["file"])
                  for r in fixed["receipts"]}
        result=aggregate(lock,manifest,metas,receipts)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.out,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            json.dump(result,out,sort_keys=True,indent=2)
            out.write("\n")
        print(json.dumps({
            "status":result["status"],
            "actual_upstream_regressions":4,"distinct_repositories":3,
            "source_grounded_open_review_questions":6,
            "independent_expert_gold_labels":0,
            "trained_model_gain":False,
            "source_proof_file":str(args.out),
        },indent=2))
        return 0
    except (ValueError,OSError,UnicodeError,TypeError,IndexError,KeyError) as exc:
        p.exit(1,"FALSUM FOUR-STAGE SOURCE TEST EVIDENCE BLOCKED: "+str(exc)[:180]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
