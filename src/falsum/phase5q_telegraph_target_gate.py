"""Phase 5Q: bounded canonical-Intent security-review *relevance* preflight.

It rejects task-mismatched public Telegraph response captures. This is NOT a
semantic correctness judge, WASM/safetensors network scorer, live registry,
source-validation of vulnerabilities or proof of ranking improvement.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import (
    SPECS, SOURCE_BASE, VIEW_BASE, inspect_fixture, fetch_bytes, git_blob_sha,
    EXCLUDED_MINERS, EvidenceError,
)
from .phase5m_real_source_sensitive_model import ROOT

PROTOCOL_PATH="data/phase5q-preimplementation-telegraph-target-contract.json"
PROTOCOL_BLOB_SHA1="7c88b3508b6e8cfb842c51b68dc6224b130a0d64"
SOURCE_COMMIT="99d2e3c93890a8fc083947bde4f21217516b7a5f"
ROLE_ORDER=("canonical_same_intent","direct_different_envelope","routed_other_intent")
ORIGINAL_ROLE={"canonical_same_intent":"routed_security",
               "direct_different_envelope":"direct_verity",
               "routed_other_intent":"routed_code"}
STUDY_STATUS="PHASE5Q_ORIGINAL_PUBLIC_TELEGRAPH_ROUTE_RELEVANCE_DIAGNOSTIC"
CANONICAL="SECURITY_REVIEW_GENERAL"
MAX_DIFF=32768
MAX_RESPONSE=4000000
MAX_LINES=1800
MAX_FILES=20
ADVISORY_RE=re.compile(r"^GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$")
DIFF_FILE_RE=re.compile(r"^diff --git a/(\S+) b/(\S+)$")
HUNK_RE=re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
PREFERRED_TEXT=("explanation","message","description","summary","reason","claim")


class TargetRelevanceError(ValueError):
    pass


def require(ok:bool, reason:str)->None:
    if not ok:
        raise TargetRelevanceError(reason)


def json_bytes(value:dict)->bytes:
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,
        separators=(",",":"))).encode("utf-8")


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def protocol(root:Path=ROOT)->dict:
    blob=(root/PROTOCOL_PATH).read_bytes()
    require(git_blob_sha(blob)==PROTOCOL_BLOB_SHA1,
            "original preimplementation source-and-policy freeze changed")
    raw=json.loads(blob)
    require(raw.get("schema_version")==1 and
            raw.get("status")=="PHASE5Q_FROZEN_CANONICAL_TELEGRAPH_RELEVANCE_AUDIT_BEFORE_IMPLEMENTATION" and
            raw.get("intent")==CANONICAL and
            raw.get("source_commit")==SOURCE_COMMIT and
            raw.get("source_repo")=="anvithagowda098/pr-guard" and
            raw.get("excluded_miners")==["731001"] and
            raw.get("no_network_ranking_modification") is True and
            raw.get("no_known_independent_expert_gold") is True and
            raw.get("training_use_allowed") is False and
            raw.get("may_publish_aggregate_link_only") is True and
            set(raw.get("original_external_capture_roles",{}))==set(ROLE_ORDER),
            "frozen original Telegraph comparison contract invalid")
    for role,mapping in ORIGINAL_ROLE.items():
        entry=raw["original_external_capture_roles"][role]
        spec=SPECS[mapping]
        require(entry.get("git_blob_sha1")==spec["blob"]
                and entry.get("source_path")==spec["path"]
                and entry.get("miner_id")==spec["miner_id"]
                and entry.get("requested_intent")==spec["intent"]
                and entry.get("result_shape")==spec["shape"]
                and spec["miner_id"] not in EXCLUDED_MINERS,
                "preselected original public capture definition changed")
    return raw


def parse_diff(value:object)->dict:
    """Parse added/new-line anchors only, not an exploited/applicable finding."""
    require(isinstance(value,str) and 0<len(value.encode("utf-8"))<=MAX_DIFF
            and "\x00" not in value and "\r" not in value,
            "security review input missing, contains control bytes or is too large")
    lines=value.splitlines()
    require(len(lines)<=MAX_LINES and len(lines)>2,
            "invalid number of source diff lines")
    files={}
    current=None
    new_line=None
    for line in lines:
        match=DIFF_FILE_RE.fullmatch(line)
        if match:
            path1,path2=match.groups()
            require(path1==path2 and
                    not path1.startswith(("/",".","\\")) and
                    ".." not in path1.split("/") and
                    re.fullmatch(r"[A-Za-z0-9_.@+/-]+",path1) is not None and
                    len(path1)<=220 and
                    len(files)<MAX_FILES and path1 not in files,
                    "unsafe or duplicate patch path")
            current=path1
            new_line=None
            files[path1]={}
            continue
        if current is None:
            # Header-free text before initial diff path is not trusted.
            require(not line.strip(),"unexpected preamble before diff")
            continue
        m=HUNK_RE.match(line)
        if m:
            new_line=int(m.group(1))
            require(0<new_line<=1000000,"new source line index invalid")
            continue
        if line.startswith(("+++ ","--- ","index ","new file mode ","deleted file mode ")):
            continue
        if line.startswith("\\ No newline"):
            continue
        if new_line is None:
            require(not line.startswith(("+","-")),"missing exact source hunk header")
            continue
        if line.startswith("+") and not line.startswith("+++"):
            data=line[1:]
            if data.strip():
                require(new_line not in files[current],"duplicate added line in patch")
                files[current][new_line]=data
            new_line+=1
        elif line.startswith("-") and not line.startswith("---"):
            continue
        elif line.startswith(" "):
            new_line+=1
        elif line=="":
            continue
        else:
            raise TargetRelevanceError("malformed source diff hunk body")
    require(files and any(lines for lines in files.values()),
            "no positive added-line evidence to evaluate")
    return files


def _description(entry:dict)->str:
    return " ".join(str(entry[k])[:1000] for k in PREFERRED_TEXT
                    if isinstance(entry.get(k),str))


def _advisory_feed(payload:object)->bool:
    if not isinstance(payload,list) or len(payload)<10:
        return False
    n=sum(1 for x in payload if isinstance(x,dict)
          and isinstance(x.get("ghsa_id"),str)
          and ADVISORY_RE.fullmatch(x["ghsa_id"]))
    return n>=10 and n/len(payload)>=0.8


def _findings(payload:object)->list|None:
    if not isinstance(payload,dict):
        return None
    if isinstance(payload.get("findings"),list):
        return payload["findings"]
    if isinstance(payload.get("answer"),dict):
        answer=payload["answer"]
        if isinstance(answer.get("findings"),list):
            return answer["findings"]
    return None


def classify(request:object,body:object)->dict:
    """Public reusable local task-relevance gate. A positive is NOT gold."""
    require(isinstance(request,dict),"review request must be JSON object")
    require(isinstance(body,dict),"miner response body must be JSON object")
    intent=request.get("intent")
    if intent!=CANONICAL:
        return {"decision":"NOT_COMPARABLE_DIFFERENT_INTENT",
                "source_citation_count":0,"structural_findings":0,
                "semantic_correctness":None,"network_rank_delta":None}
    params=request.get("params")
    if not isinstance(params,dict) or not isinstance(params.get("target"),str):
        return {"decision":"NOT_COMPARABLE_DIFFERENT_REQUEST",
                "source_citation_count":0,"structural_findings":0,
                "semantic_correctness":None,"network_rank_delta":None}
    diff=params["target"]
    parsed=parse_diff(diff)
    raw=body.get("result")
    if _advisory_feed(raw):
        # It is an advisory-feed result, not a diff review: source location
        # heuristics or keyword-padding cannot make this a valid diff analysis.
        verdict="OFF_TARGET_ADVISORY_FEED"
        citations=0
        find_count=0
    else:
        entries=_findings(raw)
        citations=0
        find_count=0
        if entries is not None and len(entries)<=120:
            find_count=len(entries)
            for item in entries:
                if not isinstance(item,dict):
                    continue
                p=item.get("file_path",item.get("file",item.get("path")))
                n=item.get("line")
                evidence=item.get("source_line",item.get("evidence"))
                d=_description(item)
                if (type(p) is str and p in parsed and
                    type(n) is int and n in parsed[p] and
                    type(evidence) is str and
                    evidence.strip()==parsed[p][n].strip() and
                    24<=len(d)<=2500 and
                    d.strip()!=evidence.strip() and
                    len(d.split())>=4):
                    citations+=1
        verdict=("REVIEW_STRUCTURE_PRESENT_NOT_SEMANTIC_GOLD" if citations
                 else "INSUFFICIENT_EVIDENCE")
    return {
        "decision":verdict,
        "source_citation_count":citations,
        "structural_findings":find_count,
        "source_paths_count":len(parsed),
        "added_code_lines_count":sum(map(len,parsed.values())),
        "request_sha256":sha(diff.encode("utf-8")),
        "source_reference_is_self_attested_not_external_gold":True,
        "semantic_correctness":None,
        "network_rank_delta":None,
        "paid_or_http_status_used_as_quality_proxy":False,
        "canonical_intent":CANONICAL,
    }


def original_public_diagnostic(*,get=fetch_bytes,root:Path=ROOT)->dict:
    """Never republish third-party request/response text. Link and aggregate only."""
    lock=protocol(root)
    captures={}
    integrity=[]
    for kind,role in ORIGINAL_ROLE.items():
        spec=SPECS[role]
        raw=get(SOURCE_BASE+spec["path"])
        require(isinstance(raw,bytes) and len(raw)<=2500000,
                "source fixture is not bounded binary")
        check=inspect_fixture(role,spec,raw)
        original=json.loads(raw)
        if kind=="canonical_same_intent":
            decision=classify(original["request"],original["body"])
        elif kind=="direct_different_envelope":
            decision={"decision":"NOT_COMPARABLE_DIFFERENT_REQUEST",
                      "semantic_correctness":None}
        else:
            decision=classify(original["request"],original["body"])
        require(decision["decision"]==lock["original_external_capture_roles"][kind]["protocol_prediction"],
                "precommitted public relevance outcome mismatch")
        captures[kind]={
            "source_url":VIEW_BASE+spec["path"],
            "source_git_blob_sha1":spec["blob"],
            "captured_miner_id":spec["miner_id"],
            "request_intent":spec["intent"],
            "input_sha256":check["request_input_sha256"],
            "reported_paid_flag":check["recorded_payment_flags_present"],
            "verified_original_source_bytes":True,
            "decision":decision["decision"],
            "semantic_gold":False,
            "live_network_ranking_changed":False,
            "capture_quality_not_proven_by_http_200":True,
            "same_intent_and_same_envelope_comparable":kind=="canonical_same_intent",
        }
        integrity.append(check["request_input_sha256"])
    require(len(set(integrity))==1,
            "original source captures are not based on identical exact code diff")
    canonical=captures["canonical_same_intent"]
    require(canonical["decision"]=="OFF_TARGET_ADVISORY_FEED",
            "public same-Intent off-target response was not rejected")
    return {
        "schema_version":1,"status":STUDY_STATUS,
        "phase5q_frozen_preimplementation_git_blob_sha1":PROTOCOL_BLOB_SHA1,
        "source_repository":"anvithagowda098/pr-guard",
        "source_revision":SOURCE_COMMIT,
        "public_issue":"https://github.com/telegraphprotocol/bounties/issues/187",
        "source_owner_independent_of_falsum":True,
        "same_diff_sha256":integrity[0],
        "original_capture_count":3,
        "true_canonical_security_review_general_count":1,
        "original_canonical_http200_and_paid_flags":True,
        "naive_http200_would_accept_off_target_capture":True,
        "original_canonical_off_target_capture_rejected":True,
        "noncomparable_different_intent_or_channel_count":2,
        "same_intent_multi_miner_ranking_comparison_available":False,
        "actual_positive_eligible_same_intent_control_present":False,
        "baseline_accuracy_or_generalization_claim":False,
        "real_network_request_sent_by_falsum":False,
        "node_receipts_cryptographically_verified":False,
        "private_node_material_accessed":False,
        "original_owner_miner_731001_excluded":True,
        "original_third_party_response_body_republished":False,
        "training_or_scoring_third_party_outputs":False,
        "expert_labels_or_semantic_accuracy_verified":False,
        "candidate_evaluator_registered":False,
        "real_telegraph_ranking_changed":False,
        "official_h2_submitted":False,
        "source_capture_diagnostics":captures,
    }


def _read_obj(path:Path,limit:int)->dict:
    require(path.is_file() and not path.is_symlink() and
            0<path.stat().st_size<=limit,"invalid, symlinked or oversized local JSON")
    value=json.loads(path.read_bytes())
    require(isinstance(value,dict),"local JSON is not an object")
    return value


def main(args:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="FALSUM canonical Telegraph review-response task-relevance preflight")
    p.add_argument("--out",required=True,type=Path,
                   help="write-once report path; never print original third-party bodies")
    p.add_argument("--request-json",type=Path,
                   help="optional local canonical request JSON for unverified candidate triage")
    p.add_argument("--response-json",type=Path,
                   help="optional local miner body JSON; no network call or model score")
    options=p.parse_args(args)
    try:
        require(not options.out.exists() and
                not options.out.is_symlink() and
                options.out.suffix.lower()==".json",
                "output must be a fresh JSON file")
        require((options.request_json is None)==(options.response_json is None),
                "local request and response must be supplied together")
        protocol()
        if options.request_json is None:
            result=original_public_diagnostic()
        else:
            req=_read_obj(options.request_json,MAX_DIFF+4000)
            body=_read_obj(options.response_json,MAX_RESPONSE)
            result={
                "schema_version":1,"status":"PHASE5Q_USER_SUPPLIED_LOCAL_RESPONSE_RELEVANCE_NOT_EXPERT_GOLD",
                "source_attestation":"LOCAL_ONLY_NOT_EXTERNALLY_VERIFIED",
                "report":classify(req,body),
                "actual_telegraph_paid_request_verified":False,
                "real_model_quality":None,
                "real_network_ranking_changed":False,
                "original_third_party_input_republished":False,
            }
        options.out.parent.mkdir(parents=True,exist_ok=True)
        options.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":result["status"],
            "original_canonical_off_target_capture_rejected":
                result.get("original_canonical_off_target_capture_rejected",None),
            "decision":result.get("report",{}).get("decision"),
            "ranking_changed":False},sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,AssertionError,
            EvidenceError,TargetRelevanceError) as exc:
        p.exit(1,"PHASE5Q FAILED CLOSED: "+str(exc)[:260]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
