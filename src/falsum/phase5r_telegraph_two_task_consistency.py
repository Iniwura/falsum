"""Authentic, public Telegraph canonical-response task sensitivity across TWO targets.

Original public PR Guard captures: same canonical SECURITY_REVIEW_GENERAL
route, same reported Miner #77003, DIFFERENT tasks. Checks both original Git
blobs and source-locked response lists. No model-rank, semantic accuracy,
payment settlement or independent FALSUM adoption claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import (
    SOURCE_BASE, VIEW_BASE, fetch_bytes, git_blob_sha, SPECS, inspect_fixture,
)
from .phase5q_telegraph_target_gate import (
    CANONICAL, classify as classify_code, TargetRelevanceError, sha,
    _advisory_feed, protocol as phase5q_protocol,
)
from .phase5m_real_source_sensitive_model import ROOT

LOCK_PATH="data/phase5r-observed-independent-two-task-contrast-lock.json"
LOCK_BLOB="94b90f7276b001e1660eb53497a20611f3a6973a"
EXTERNAL_REV="99d2e3c93890a8fc083947bde4f21217516b7a5f"
STATUS="PHASE5R_TWO_INDEPENDENT_TASKS_SAME_EXTERNAL_MINER_IDENTICAL_IRRELEVANT_ADVISORIES"
PACKAGE_RE=re.compile(r"^npm package ([a-z0-9_.@/+-]{1,90}) version ([0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:-[a-z0-9.-]+)?)$",re.I)
ALLOWED_ROLES=("security-code-diff","security-npm-dependency")


def require(predicate:bool, reason:str)->None:
    if not predicate:
        raise TargetRelevanceError(reason)


def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK_PATH).read_bytes()
    require(git_blob_sha(raw)==LOCK_BLOB,
            "original two-task preimplementation observational source lock changed")
    p=json.loads(raw)
    require(p.get("schema_version")==1 and
            p.get("status")=="PHASE5R_PREIMPLEMENTATION_PUBLIC_OBSERVED_EXTERNAL_TWO_TASK_CONTRAST" and
            p.get("source_revision")==EXTERNAL_REV and
            p.get("source_repo")=="anvithagowda098/pr-guard" and
            p.get("intent")==CANONICAL and
            p.get("restrictions",{}).get("not_new_blind_holdout") is True and
            p.get("restrictions",{}).get("independent_expert_gold")==0 and
            p.get("restrictions",{}).get("do_not_republish_bodies") is True,
            "original observational protocol drift or inflated claims")
    entries=p.get("original_fixtures")
    require(isinstance(entries,list) and len(entries)==2 and
            tuple(x.get("key") for x in entries)==ALLOWED_ROLES and
            entries[0].get("blob_sha1")==SPECS["routed_security"]["blob"] and
            entries[0].get("path")==SPECS["routed_security"]["path"] and
            entries[1].get("blob_sha1")=="0b3268f57d3e21d906e51be9aebf754347e5787d" and
            entries[1].get("path")=="test/fixtures/miner-responses/ROUTED/security-review-lodash-77003-off-target.json" and
            all(x.get("miner")=="77003" and x.get("intent")==CANONICAL
                    and x.get("expected")=="OFF_TARGET_ADVISORY_FEED" for x in entries),
            "wrong original public two-task fixture identity")
    expected=p["original_capture_aggregate_expectations"]
    require(expected.get("externally_captured_paid_responses")==2 and
            expected.get("common_advisory_ids")==100 and
            expected.get("exact_advisory_order_identical") is True and
            expected.get("original_package_name_mentions_in_100_entry_dependency_result")==0,
            "preobserved expected original result silently changed")
    return p


def _package_specific_item(entry:dict,package:str,version:str)->bool:
    """Presence of named package is *structural relevance only*, NOT vulnerability gold."""
    vulnerabilities=entry.get("vulnerabilities")
    if isinstance(vulnerabilities,list):
        for hit in vulnerabilities:
            if isinstance(hit,dict):
                pkg=hit.get("package")
                if isinstance(pkg,dict) and str(pkg.get("name","")).casefold()==package.casefold():
                    return True
    text=" ".join(str(entry.get(k,""))[:1200] for k in
                  ("summary","description","package","name"))
    return bool(re.search(r"(?<![a-z0-9])"+re.escape(package)+r"(?![a-z0-9])",
                          text,re.I))


def classify_package(request:object,body:object)->dict:
    """Dependency-specific task relevance, with no external accuracy claims."""
    require(isinstance(request,dict) and isinstance(body,dict),
            "expected canonical request/body objects")
    if request.get("intent")!=CANONICAL:
        return {"decision":"NOT_COMPARABLE_DIFFERENT_INTENT",
                "semantic_accuracy":None,"network_ranking_delta":None}
    data=request.get("params")
    if not isinstance(data,dict) or not isinstance(data.get("target"),str):
        return {"decision":"NOT_COMPARABLE_DIFFERENT_REQUEST",
                "semantic_accuracy":None,"network_ranking_delta":None}
    target=data["target"]
    match=PACKAGE_RE.fullmatch(target)
    if not match:
        if target.startswith("diff --git "):
            return classify_code(request,body)
        return {"decision":"INSUFFICIENT_EVIDENCE",
                "semantic_accuracy":None,"network_ranking_delta":None,
                "reason":"unsupported canonical task syntax, cannot infer target"}
    package,version=match.groups()
    result=body.get("result")
    hits=0
    if isinstance(result,list):
        hits=sum(1 for entry in result if isinstance(entry,dict)
                 and _package_specific_item(entry,package,version))
    if _advisory_feed(result) and hits==0:
        verdict="OFF_TARGET_ADVISORY_FEED"
    elif hits>0:
        verdict="DEPENDENCY_RELEVANCE_PRESENT_NOT_SEMANTIC_GOLD"
    elif isinstance(result,dict) and (
        str(result.get("package",result.get("name",""))).casefold()==package.casefold()
        and bool(result.get("findings") or result.get("vulnerabilities"))):
        verdict="DEPENDENCY_RELEVANCE_PRESENT_NOT_SEMANTIC_GOLD"
    else:
        verdict="INSUFFICIENT_EVIDENCE"
    return {
        "decision":verdict,
        "canonical_intent":CANONICAL,
        "target_class":"npm-dependency-security",
        "input_sha256":sha(target.encode("utf-8")),
        "source_target_package_sha256":sha(package.lower().encode("utf-8")),
        "source_target_version_sha256":sha(version.encode("utf-8")),
        "result_is_generic_advisory_feed":_advisory_feed(result),
        "target_specific_advisory_mentions":hits,
        "semantic_accuracy":None,
        "network_ranking_delta":None,
        "paid_http_status_used_as_quality":False,
        "package_reference_is_not_verified_security_gold":True,
    }


def original_pair(*,fetch=fetch_bytes,root:Path=ROOT)->dict:
    p=frozen(root)
    phase5q_protocol(root)
    entries=[]
    ghsa_lists=[]
    inputs=[]
    for spec in p["original_fixtures"]:
        raw=fetch(SOURCE_BASE+spec["path"])
        require(isinstance(raw,bytes) and 0<len(raw)<=2500000 and
                git_blob_sha(raw)==spec["blob_sha1"],
                "original public Telegraph fixture differs from pinned Git bytes")
        try:
            data=json.loads(raw)
        except (ValueError,UnicodeError,TypeError) as e:
            raise TargetRelevanceError("original public fixture JSON corrupted") from e
        request=data.get("request")
        body=data.get("body")
        require(isinstance(request,dict) and isinstance(body,dict) and
                request.get("intent")==CANONICAL and
                isinstance(request.get("params"),dict) and
                isinstance(request["params"].get("target"),str) and
                str(body.get("miner_id"))==spec["miner"] and
                body.get("result_shape")=="raw" and
                data.get("status")==200 and data.get("paid") is True and
                data.get("ok") is True and data.get("charged") is True,
                "changed original canonical paid response identity")
        require(body.get("result") is not None and
                isinstance(body["result"],list) and
                len(body["result"])==100 and _advisory_feed(body["result"]),
                "original external output is not the expected generic advisory-list shape")
        if spec["key"]=="security-code-diff":
            check=inspect_fixture("routed_security",SPECS["routed_security"],raw)
            require(check["request_input_sha256"]==sha(request["params"]["target"].encode()),
                    "original source identity differs from Phase 4L evidence")
            result=classify_code(request,body)
        else:
            require(request["params"]["target"]=="npm package lodash version 4.17.15",
                    "canonical package target unexpectedly changed")
            result=classify_package(request,body)
        require(result["decision"]==spec["expected"],
                "original external task mismatch was not caught by code gate")
        ids=[]
        for item in body["result"]:
            ghsa=item.get("ghsa_id")
            require(isinstance(ghsa,str) and ghsa.startswith("GHSA-"),
                    "missing original GHSA advisory identity")
            ids.append(ghsa)
        require(len(set(ids))==100,"original GHSA feed has repeated advisory identities")
        ghsa_lists.append(ids)
        inputs.append(request["params"]["target"])
        entries.append({
            "task_kind":spec["task_category"],
            "intent":CANONICAL,
            "response_miner_id":"77003",
            "source_link":VIEW_BASE+spec["path"],
            "original_git_blob_sha1":spec["blob_sha1"],
            "source_git_blob_verified":True,
            "original_reported_http_200_and_paid":True,
            "task_sha256":sha(inputs[-1].encode("utf-8")),
            "generic_GHSA_feed_count":len(ids),
            "GHSA_id_list_sha256":sha("\n".join(ids).encode("utf-8")),
            "falsum_task_relevance_decision":result["decision"],
            "source_code_or_package_semantic_correctness_gold":False,
            "cryptographically_verified_payment":False,
        })
    require(inputs[0]!=inputs[1] and
            sha(inputs[0].encode())!=sha(inputs[1].encode()),
            "two original security tasks were not distinct")
    overlap=len(set(ghsa_lists[0])&set(ghsa_lists[1]))
    same_order=ghsa_lists[0]==ghsa_lists[1]
    require(overlap==100 and same_order,
            "frozen observed GHSA-list duplication no longer matches original sources")
    require(all(row["falsum_task_relevance_decision"]=="OFF_TARGET_ADVISORY_FEED"
                for row in entries),
            "frozen two-task off-target rejection incomplete")
    return {
        "schema_version":1,"status":STATUS,
        "observational_not_blind":True,
        "preimplementation_frozen_protocol_sha1":LOCK_BLOB,
        "original_source_repo":"anvithagowda098/pr-guard",
        "original_git_revision":EXTERNAL_REV,
        "third_party_public_issue":"https://github.com/telegraphprotocol/bounties/issues/187",
        "original_external_canonical_paid_capture_count":2,
        "original_distinct_tasks":2,
        "distinct_canonical_security_review_intents":1,
        "distinct_reporting_miners":1,
        "naive_success_http200_would_pass_both":True,
        "source_bound_target_relevance_rejected_both":True,
        "task_insensitive_100_GHSA_id_list_exactly_equal_and_same_order":True,
        "common_GHSA_ids_count":overlap,
        "response_task_specificity_concern_grounded_in_original_external_public_bytes":True,
        "benchmark_model_accuracy_proven":False,
        "valid_same_request_multi_miner_ranking_pair":False,
        "new_ranked_network_quality_improvement":False,
        "independent_expert_gold_count":0,
        "candidate_scoring_adapter_registered":False,
        "third_party_source_used_for_model_training":False,
        "full_third_party_capture_republished":False,
        "new_paid_network_requests_from_falsum":False,
        "independent_adoption_of_falsum":False,
        "official_h2_entry_submitted":False,
        "original_aggregate_rows":entries,
    }


def main(argv:list[str]|None=None)->int:
    ap=argparse.ArgumentParser(description="Actual two-task externally captured paid Telegraph answer-identity/relevance check")
    ap.add_argument("--out",type=Path,required=True)
    args=ap.parse_args(argv)
    try:
        require(args.out.suffix==".json" and not args.out.exists() and not args.out.is_symlink(),
                "report output must be a new write-once JSON")
        report=original_pair()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({
            "authentic_canonical_paid_tasks":2,
            "same_original_miner":True,
            "same_unrelated_100_GHSA_advisory_ids":True,
            "off_target_tasks_flagged":2,
            "new_network_ranking_proven":False,
        },sort_keys=True))
        return 0
    except (TargetRelevanceError,OSError,UnicodeError,ValueError,TypeError,KeyError) as exc:
        ap.exit(1,"PHASE5R FAILED CLOSED: "+str(exc)[:250]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
