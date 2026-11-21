"""Phase 5T: a real application-consumption decision, not just a quality dashboard.

Public, offline, *canonical-Intent-shaped* source-witness requests are locally
constructed. The ONLY third-party source responses are two authentic original
PR Guard published paid-status records. This code neither makes Telegraph
requests nor scores independent AppSec correctness or network miner rankings.

A positive requires precisely authenticated, executed upstream source/test and
receipt evidence, bound to the exact requested Git revision and question. A
successful HTTP/payment response, a glossy review, or borrowed proof cannot
authorize the application.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import (
    SOURCE_BASE, VIEW_BASE, fetch_bytes, git_blob_sha,
)
from .phase4v_real_source_witness_site import (
    ROOT, INDEX as WITNESS_INDEX, LOCK as WITNESS_LOCK,
)
from .phase5m_real_source_sensitive_model import sha, canonical_json
from .phase5q_telegraph_target_gate import (
    CANONICAL, classify as classify_diff, TargetRelevanceError,
)
from .phase5r_telegraph_two_task_consistency import (
    frozen as frozen_public_pair, original_pair, classify_package,
)
from .source_review_witness_gate import (
    canonical_claim, evaluate, validated_index, read, SourceWitnessError,
)

FROZEN="data/phase5t-preimplementation-source-consumption-lock.json"
FROZEN_GIT_BLOB="8383f599f8abf60278008fbbf284081882daa62e"
STATUS="PHASE5T_AUTHENTIC_SOURCE_WITNESS_APP_CONSUMPTION_AND_PUBLIC_PAID_CAPTURE"
SOURCE_TASK_RE=re.compile(
    r"^Review upstream security regression "
    r"(koa-redirect|hono-csrf|langchain-path|langchain-symlink) "
    r"at Git revision ([0-9a-f]{40})\.$"
)
ACTIONS=("ALLOW","DENY")
DECISIONS=(
    "ACCEPT_SOURCE_WITNESSED_FACT",
    "REJECT_CONTRADICTED_FACT",
    "REJECT_UNVERIFIED_PROOF",
    "REJECT_TASK_MISMATCH",
    "REJECT_NONCOMPARABLE_REQUEST",
    "REJECT_INVALID_INPUT",
)
EXPECTED={
    "verified-narrow-facts":"ACCEPT_SOURCE_WITNESSED_FACT",
    "source-contradicted-facts":"REJECT_CONTRADICTED_FACT",
    "source-proof-tampered-facts":"REJECT_UNVERIFIED_PROOF",
    "real-pr-guard-paid-off-target":"REJECT_TASK_MISMATCH",
}


def require(ok:bool,why:str)->None:
    if not ok:
        raise TargetRelevanceError(why)


def freeze(root:Path=ROOT)->dict:
    raw=(root/FROZEN).read_bytes()
    require(git_blob_sha(raw)==FROZEN_GIT_BLOB,
            "Phase 5T preregistered application acceptance policy changed")
    p=json.loads(raw)
    require(isinstance(p,dict)
            and p.get("schema_version")==1
            and p.get("status")==
                "PHASE5T_SOURCE_BOUND_APPLICATION_CONSUMPTION_PROTOCOL_FROZEN_BEFORE_IMPLEMENTATION"
            and p.get("intent")==CANONICAL
            and p.get("source_cases")==[
                "koa-redirect","hono-csrf","langchain-path","langchain-symlink"]
            and p.get("total_conditions")==26
            and p.get("expected_actions")=={"ALLOW":8,"DENY":18}
            and p.get("actual_external_request_count")==2
            and p.get("synthetic_benchmark_conditions")==24
            and p.get("independently_validated_appsec_gold_count")==0
            and p.get("new_project_disjoint_cases")==0
            and p.get("network_evaluator_registered") is False
            and p.get("no_new_paid_telegraph_request") is True
            and p.get("no_third_party_full_response_bodies_published") is True
            and p.get("private_hidden_eval_material_used") is False
            and p.get("no_official_h2_submission") is True,
            "original preregistration schema/limits changed")
    groups=p.get("judge_benchmark_groups",[])
    require(len(groups)==4 and
            [(r.get("kind"),r.get("count"),r.get("reference_decision"))
             for r in groups]==[
                ("verified-narrow-facts",8,"ACCEPT_SOURCE_WITNESSED_FACT"),
                ("source-contradicted-facts",8,"REJECT_CONTRADICTED_FACT"),
                ("source-proof-tampered-facts",8,"REJECT_UNVERIFIED_PROOF"),
                ("real-pr-guard-paid-off-target",2,"REJECT_TASK_MISMATCH"),
             ],"expected actual/synthetic scenario groups changed")
    return p


def source_index(*,root:Path=ROOT)->dict:
    return validated_index(read(root/WITNESS_INDEX,30_000),
                           read(root/WITNESS_LOCK,70_000))


def request_for_case(case_id:str,commit:str)->dict:
    require(SOURCE_TASK_RE.fullmatch(
        "Review upstream security regression "+case_id+
        " at Git revision "+commit+".") is not None,
        "cannot encode requested source-witness input")
    return {"intent":CANONICAL,
            "params":{"target":
                f"Review upstream security regression {case_id} at Git revision {commit}."}}


def _decision(label:str,*,kind:str,request:object,validated:bool=False,
              source_verdict:str|None=None)->dict:
    require(label in DECISIONS,"unsupported source-bound application decision")
    action="ALLOW" if label=="ACCEPT_SOURCE_WITNESSED_FACT" else "DENY"
    target=(request.get("params",{}).get("target","")
            if isinstance(request,dict) and
            isinstance(request.get("params"),dict) else "")
    if not isinstance(target,str):
        target=""
    return {
        "decision":label,"action":action,"input_class":kind,
        "request_target_sha256":sha(target.encode("utf-8")),
        "original_source_witness_recomputed":bool(validated),
        "source_claim_verdict":source_verdict,
        "allow_requires_authenticated_upstream_source_and_test_receipt":True,
        "transport_or_payment_success_is_not_acceptance":True,
        "independent_appsec_semantic_gold":False,
        "registered_network_evaluator":False,
        "external_miner_ranking_improvement":False,
    }


def decide(request:object,body:object,index:dict)->dict:
    """Stateless application decision; locally bounded nonthrowing unknown inputs."""
    if not isinstance(request,dict) or not isinstance(body,dict):
        return _decision("REJECT_INVALID_INPUT",kind="malformed",request={})
    if request.get("intent")!=CANONICAL:
        return _decision("REJECT_NONCOMPARABLE_REQUEST",
                         kind="wrong-Intent",request=request)
    params=request.get("params")
    if not isinstance(params,dict) or set(params)!={"target"} or \
            type(params["target"]) is not str:
        return _decision("REJECT_NONCOMPARABLE_REQUEST",
                         kind="wrong-envelope",request=request)
    target=params["target"]
    if len(target.encode("utf-8"))>32768:
        return _decision("REJECT_INVALID_INPUT",
                         kind="oversized-input",request={})
    match=SOURCE_TASK_RE.fullmatch(target)
    if match:
        case_id,commit=match.groups()
        witness=index.get(case_id)
        if witness is None or commit not in (
                witness["original_git_commit"],witness["fixed_git_commit"]):
            return _decision("REJECT_UNVERIFIED_PROOF",
                             kind="unverified-Git-revision",request=request)
        output=body.get("result")
        if not isinstance(output,dict) or set(output)!={"review_claim"}:
            return _decision("REJECT_UNVERIFIED_PROOF",
                             kind="missing-or-extra-structured-claim",request=request)
        claim=output["review_claim"]
        if not isinstance(claim,dict) or claim.get("case_id")!=case_id or \
                claim.get("upstream_commit")!=commit:
            return _decision("REJECT_TASK_MISMATCH",
                             kind="claim-borrowed-from-different-task",request=request)
        try:
            verified=evaluate(index,claim)
        except (SourceWitnessError,ValueError,TypeError,KeyError):
            return _decision("REJECT_UNVERIFIED_PROOF",
                             kind="malformed-original-evidence",request=request)
        mapping={
            "SUPPORTED":"ACCEPT_SOURCE_WITNESSED_FACT",
            "CONTRADICTED":"REJECT_CONTRADICTED_FACT",
            "ABSTAIN":"REJECT_UNVERIFIED_PROOF",
        }
        return _decision(mapping[verified["verdict"]],
                         kind="local-source-execution-reference-not-paid-provider",
                         request=request,validated=True,
                         source_verdict=verified["verdict"])

    # For real public Telegraph captures, preserve original request envelope
    # and body. Both outside source categories have target-specific guards.
    if target.startswith("diff --git "):
        try:
            judgement=classify_diff(request,body)
        except (TargetRelevanceError,ValueError,KeyError,TypeError):
            return _decision("REJECT_INVALID_INPUT",
                             kind="invalid-Git-diff",request=request)
        kind="original-canonical-code-diff"
    elif target.startswith("npm package "):
        try:
            judgement=classify_package(request,body)
        except (TargetRelevanceError,ValueError,KeyError,TypeError):
            return _decision("REJECT_INVALID_INPUT",
                             kind="invalid-dependency-request",request=request)
        kind="original-canonical-npm-dependency"
    else:
        return _decision("REJECT_INVALID_INPUT",
                         kind="unsupported-canonical-question",request=request)
    if judgement.get("decision")=="OFF_TARGET_ADVISORY_FEED":
        return _decision("REJECT_TASK_MISMATCH",kind=kind,request=request)
    # A response with structural relevance but no independently authenticated
    # source/test receipt must never automatically authorize consumption.
    return _decision("REJECT_UNVERIFIED_PROOF",kind=kind,request=request)


def _source_case_suite(index:dict)->list[dict]:
    rows=[]
    for key in ("koa-redirect","hono-csrf","langchain-path","langchain-symlink"):
        witness=index[key]
        for revision in ("parent","fixed"):
            commit=(witness["original_git_commit"] if revision=="parent"
                    else witness["fixed_git_commit"])
            request=request_for_case(key,commit)
            good_type=("UPSTREAM_REGRESSION_FAILS" if revision=="parent"
                       else "UPSTREAM_REGRESSION_PASSES")
            bad_type=("UPSTREAM_REGRESSION_PASSES" if revision=="parent"
                      else "UPSTREAM_REGRESSION_FAILS")
            correct=canonical_claim(witness,revision,good_type)
            incorrect=canonical_claim(witness,revision,bad_type)
            corrupt=json.loads(json.dumps(correct))
            corrupt["evidence"]["actual_execution_receipt_sha256"]="0"*64
            for group,claim in (
                ("verified-narrow-facts",correct),
                ("source-contradicted-facts",incorrect),
                ("source-proof-tampered-facts",corrupt),
            ):
                rows.append({
                    "id":sha((key+":"+revision+":"+group).encode())[:24],
                    "source_case":key,"group":group,
                    "request":request,
                    "body":{"result":{"review_claim":claim}},
                    "expected":EXPECTED[group],
                    "grounding":"AUTHENTICATED_UPSTREAM_SOURCE_TEST_AND_RESEARCHER_DESIGNED_LOCAL_RESPONSE",
                    "reported_http_status":200,
                    "local_synthetic_paid_flag":True,
                })
    require(len(rows)==24 and len({r["id"] for r in rows})==24,
            "local source-consumption scenarios not complete")
    return rows


def _original_external_suite(*,get=fetch_bytes,root:Path=ROOT)->list[dict]:
    lock=frozen_public_pair(root)
    raw_by_url={}
    for spec in lock["original_fixtures"]:
        uri=SOURCE_BASE+spec["path"]
        raw=get(uri)
        require(isinstance(raw,bytes) and 0<len(raw)<=2500000 and
                git_blob_sha(raw)==spec["blob_sha1"],
                "public original external capture source byte identity lost")
        raw_by_url[uri]=raw
    audit=original_pair(fetch=lambda url:raw_by_url[url],root=root)
    require(audit["source_bound_target_relevance_rejected_both"] is True and
            audit["common_GHSA_ids_count"]==100 and
            audit["original_distinct_tasks"]==2,
            "original public paid-flagged capture pair no longer valid")
    out=[]
    for spec in lock["original_fixtures"]:
        original=json.loads(raw_by_url[SOURCE_BASE+spec["path"]])
        out.append({
            "id":sha(("original-external:"+spec["key"]).encode())[:24],
            "source_case":spec["key"],
            "group":"real-pr-guard-paid-off-target",
            "request":original["request"],"body":original["body"],
            "expected":"REJECT_TASK_MISMATCH",
            "grounding":"ACTUAL_ORIGINAL_THIRD_PARTY_PUBLIC_GIT_BLOB_VERIFIED_PAID_CAPTURE",
            "reported_http_status":original["status"],
            "local_synthetic_paid_flag":False,
            "original_reported_paid_flag":original["paid"],
            "source_url":VIEW_BASE+spec["path"],
            "original_source_git_blob_sha1":spec["blob_sha1"],
        })
    return out


def _baseline_always_transport_ok(row:dict)->str:
    """Naive success gate; local paid flag explicitly synthetic."""
    reported_paid=(row["local_synthetic_paid_flag"] if
                   row["group"]!="real-pr-guard-paid-off-target"
                   else row["original_reported_paid_flag"])
    return ("ALLOW" if row["reported_http_status"]==200 and reported_paid
            else "DENY")


def _baseline_claim_present(row:dict)->str:
    body=row["body"]
    return ("ALLOW" if isinstance(body.get("result"),dict)
            and isinstance(body["result"].get("review_claim"),dict)
            else "DENY")


def _scored_baseline(rows:list[dict],policy)->dict:
    observed=Counter()
    for row in rows:
        expected="ALLOW" if row["expected"]=="ACCEPT_SOURCE_WITNESSED_FACT" else "DENY"
        candidate=policy(row)
        require(candidate in ACTIONS,"baseline returned unsupported action")
        observed["correct"]+=int(candidate==expected)
        observed["false_allow"]+=int(candidate=="ALLOW" and expected=="DENY")
        observed["false_deny"]+=int(candidate=="DENY" and expected=="ALLOW")
        observed["allow"]+=int(candidate=="ALLOW")
    return {
        "total":len(rows),"constructed_and_real_conditions_mixed":True,
        "correct_to_constructed_or_original_target_expectations":observed["correct"],
        "false_allow":observed["false_allow"],
        "false_deny":observed["false_deny"],
        "allow":observed["allow"],
        "independent_expert_gold":False,
        "model_accuracy_claim":False,
    }


def evidence_report(*,get=fetch_bytes,root:Path=ROOT)->dict:
    freeze(root)
    index=source_index(root=root)
    require(set(index)=={
        "koa-redirect","hono-csrf","langchain-path","langchain-symlink"},
        "unexpected executed upstream source case identity")
    rows=_source_case_suite(index)+_original_external_suite(get=get,root=root)
    require(len(rows)==26 and len({r["id"] for r in rows})==26 and
            Counter(r["group"] for r in rows)=={
                "verified-narrow-facts":8,
                "source-contradicted-facts":8,
                "source-proof-tampered-facts":8,
                "real-pr-guard-paid-off-target":2,
            },"precommitted application test case counts changed")
    decisions=[]
    matches=0
    actual_actions=Counter()
    groups=Counter()
    for item in rows:
        decision=decide(item["request"],item["body"],index)
        require(decision["decision"]==item["expected"],
                "expected local constructed contract or original external public source result failed")
        action=decision["action"]
        actual_actions[action]+=1
        groups[item["group"]]+=1
        matches+=1
        decisions.append({
            "test_id":item["id"],"source_group":item["group"],
            "original_external_source_git_verified":item["group"]==
                "real-pr-guard-paid-off-target",
            "grounding":item["grounding"],
            "external_source_url":item.get("source_url"),
            "external_source_git_blob_sha1":item.get("original_source_git_blob_sha1"),
            "request_target_sha256":decision["request_target_sha256"],
            "source_case":item["source_case"],
            "application_action":action,
            "application_reason":decision["decision"],
            "reference_expected":item["expected"],
            "is_original_paid_capture":item["group"]=="real-pr-guard-paid-off-target",
            "no_external_semantic_gold":True,
        })
    require(actual_actions=={"ALLOW":8,"DENY":18},
            "app consumed unverified or contradicted original source facts")
    baselines={
        "accept_all_successful_paid_status":_scored_baseline(rows,_baseline_always_transport_ok),
        "deny_everything":_scored_baseline(rows,lambda x:"DENY"),
        "trust_any_typed_claim_without_verification":_scored_baseline(rows,_baseline_claim_present),
    }
    return {
        "schema_version":1,"status":STATUS,
        "preimplementation_git_blob_sha1":FROZEN_GIT_BLOB,
        "evaluation_intent":CANONICAL,
        "local_application_policy":"ACCEPT_AUTHENTICATED_NARROW_SOURCE_FACT_ONLY",
        "source_witness_count":4,
        "previously_known_source_projects_not_new_holdout":True,
        "original_external_git_authenticated_paid_responses":2,
        "constructed_from_original_source_witness_and_tamper_conditions":24,
        "mixed_observational_and_constructed_conditions":26,
        "total_application_decisions":26,
        "decisions_matching_preconstructed_or_external_expectations":matches,
        "app_authorized_exact_source_supported_narrow_facts":8,
        "app_denied_all_known_original_off_target_or_unsupported_claims":18,
        "original_paid_success_off_target_rejections":2,
        "security_expert_accuracy_metric":None,
        "new_project_disjoint_security_cases":0,
        "certified_independent_gold_labels":0,
        "different_miner_same_request_ranking_comparison":False,
        "real_live_telegraph_scoring_improvement":False,
        "real_provider_selection_or_network_ranking_change":False,
        "registered_network_evaluator":False,
        "actual_telegraph_paid_calls_by_falsum":0,
        "original_paid_receipt_crypto_authenticated":False,
        "third_party_original_full_response_republished":False,
        "outside_falsum_adoption":False,
        "official_h2_entry_submitted":False,
        "original_external_source":"https://github.com/telegraphprotocol/bounties/issues/187",
        "real_original_upstream_execution_index":
            "https://github.com/Iniwura/falsum/blob/main/"+
            WITNESS_INDEX,
        "baselines":baselines,
        "case_outcomes":decisions,
    }


def _json(path:Path,max_bytes:int)->dict:
    require(path.is_file() and not path.is_symlink() and
            0<path.stat().st_size<=max_bytes,"input must be bounded, local and regular")
    x=json.loads(path.read_bytes())
    require(isinstance(x,dict),"local request JSON root must be an object")
    return x


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="FALSUM original external + locally constructed source-witness application decision policy")
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--request-json",type=Path)
    parser.add_argument("--response-json",type=Path)
    a=parser.parse_args(argv)
    try:
        require(a.out.suffix.lower()==".json" and
                not a.out.exists() and not a.out.is_symlink(),
                "output must be fresh, write-once JSON")
        require((a.request_json is None)==(a.response_json is None),
                "local request and answer must be supplied together")
        if a.request_json is None:
            output=evidence_report()
        else:
            freeze()
            index=source_index()
            local_request=_json(a.request_json,70_000)
            local_answer=_json(a.response_json,150_000)
            result=decide(local_request,local_answer,index)
            output={
                "schema_version":1,
                "status":"PHASE5T_USER_SUPPLIED_LOCAL_APP_CONSUMPTION_NOT_NETWORK_OR_GOLD",
                "local_user_supplied_not_network_verified":True,
                "provenance_of_user_input":"UNVERIFIED_LOCAL",
                "decision":result,
                "real_telegraph_ranking_change":False,
                "model_semantic_accuracy":None,
                "original_user_supplied_bodies_in_report":False,
            }
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(output,sort_keys=True,indent=2)+"\n",
                         encoding="utf-8")
        print(json.dumps({
            "status":output["status"],
            "cases":output.get("total_application_decisions"),
            "original_public_paid_responses_checked":output.get(
                "original_external_git_authenticated_paid_responses"),
            "allowed":output.get("app_authorized_exact_source_supported_narrow_facts"),
            "blocked":output.get("app_denied_all_known_original_off_target_or_unsupported_claims"),
            "local_user_action":output.get("decision",{}).get("action"),
            "registered_network_evaluator":False,
        },sort_keys=True))
        return 0
    except (OSError,UnicodeError,ValueError,TypeError,KeyError,AssertionError,
            TargetRelevanceError,SourceWitnessError) as exc:
        parser.exit(1,"PHASE5T FAIL-CLOSED APPLICATION CONSUMPTION: "+
                    str(exc)[:260]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
