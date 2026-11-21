"""Phase 5X: actual original third-party public three-provider lodash target evidence.

Three original Git-blob-verified, paid-FLAGGED PR Guard external captures:
  * a canonical routed SECURITY_REVIEW_GENERAL response (Miner 77003)
  * direct GET /query security-family responses (Miner 190048, Miner 77010)
Same package/version semantics, NOT the same canonical Intent or byte-identical
requests, therefore NOT a fair Telegraph Miner ranking experiment.

Two direct responses carry package/version-bound advisory REFERENCES. The
canonical routed response returns 100 unrelated GHSA records. Positive evidence
only permits DISPLAY of unverified referenced advisories, never claims
independent AppSec gold, package safety, exploitable vulnerability severity,
verified chain-settled payments, registered network scorer, adoption or ranking.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import (
    ROOT as SOURCE_ROOT, SOURCE_BASE,VIEW_BASE,fetch_bytes,git_blob_sha,
)
from .phase5m_real_source_sensitive_model import ROOT,sha
from .phase5q_telegraph_target_gate import TargetRelevanceError

LOCK="data/phase5x-frozen-original-three-provider-lodash-relevance.json"
FROZEN_BLOB="227b91ab42688ac4a02a95633ba3556d3ff8b84f"
ST_REPORT="PHASE5X_ORIGINAL_THREE_DIFFERENT_MINER_PAID_FLAGGED_SAME_SEMANTIC_PACKAGE_TARGET"
ST_LOCAL="PHASE5X_LOCAL_STRUCTURAL_PACKAGE_RELEVANCE_NOT_RANKING"
TARGET={"ecosystem":"npm","package":"lodash","version":"4.17.15"}
ORIGINAL_SOURCE_REPO="anvithagowda098/pr-guard"
ORIGINAL_SOURCE_COMMIT="99d2e3c93890a8fc083947bde4f21217516b7a5f"
ROLES=("canonical_routed_off_target","direct_deps_dev_ghsa","direct_deps_dev_version")
DISPLAYS=("DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES","DENY_UNSCOPED_SECURITY_ADVICE")
DENY="DENY_UNVERIFIED_REQUEST_OR_TARGET"
ADVISORY=re.compile(r"^GHSA-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$")
CVE=re.compile(r"^CVE-[0-9]{4}-[0-9]{4,8}$")
HASH64=re.compile(r"^0x[a-fA-F0-9]{64}$")


def require(ok:bool,reason:str)->None:
    if not ok:raise TargetRelevanceError(reason)


def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK).read_bytes()
    require(git_blob_sha(raw)==FROZEN_BLOB,
            "Phase 5X original paid captures, expected roles or comparison caveats altered")
    p=json.loads(raw)
    require(p.get("schema_version")==1
            and p.get("status")==
                "PHASE5X_THREE_ORIGINAL_PUBLIC_PAID_FLAGGED_LODASH_PROVIDER_TARGET_RELEVANCE_PRECOMMITTED"
            and p.get("source_repository")==ORIGINAL_SOURCE_REPO
            and p.get("source_git_commit")==ORIGINAL_SOURCE_COMMIT
            and p.get("question_target")==TARGET
            and p.get("required_original_real_source_probes")==3
            and p.get("reference_observation_count")==3
            and p.get("negative_mutations_per_original")==4
            and p.get("expected_constructed_adversarial_controls")==12
            and p.get("total_observations_and_constructed_conditions")==15
            and p.get("expected_original_display_allowed")==2
            and p.get("expected_original_off_target_rejected")==1
            and p.get("expected_constructed_mutations_denied")==12
            and p.get("trust_paid_status_baseline_original_allowed")==3
            and p.get("all_external_responses_same_target_semantics") is True
            and p.get("all_external_responses_same_protocol_intent") is False
            and p.get("all_external_requests_byte_identical") is False
            and p.get("independent_miner_owners_verified") is False
            and p.get("original_external_receipt_chain_settlement_independently_verified") is False
            and p.get("no_full_original_response_bodies_published") is True
            and p.get("no_model_training_or_accuracy_claim") is True
            and p.get("independent_appsec_gold_count")==0
            and p.get("registered_network_evaluator") is False
            and p.get("real_telegraph_miner_ranking_changed") is False
            and p.get("independent_falsum_adoption") is False
            and p.get("official_h2_submission") is False
            and p.get("no_fair_same_canonical_intent_comparison_claim") is True,
            "authentic-original evidence protocol or no-rank restrictions changed")
    xs=p.get("original_immutable_third_party_fixtures")
    require(isinstance(xs,list) and len(xs)==3
            and tuple(x.get("role") for x in xs)==ROLES
            and tuple(x.get("reported_miner_id") for x in xs)==
                 ("77003","190048","77010")
            and len({x.get("git_blob_sha1") for x in xs})==3
            and len({x.get("path") for x in xs})==3,
            "original three distinct provider/source role fingerprints absent")
    for x in xs:
        require(isinstance(x.get("git_blob_sha1"),str)
                and re.fullmatch(r"[a-f0-9]{40}",x["git_blob_sha1"])
                and x.get("expected_result_shape")=="raw"
                and x.get("expected_display_action") in DISPLAYS
                and x.get("expected_advisory_count") in (6,100)
                and x.get("reported_receipt_intent") in
                   ("SECURITY_REVIEW","SECURITY_REVIEW_GENERAL")
                and x.get("path","").startswith("test/fixtures/miner-responses/")
                and ".." not in x.get("path",""),
                "original public source path, comparison role or expected output invalid")
    require(p.get("local_synthetic_mutation_types")==[
         "change-request-package","change-request-version",
         "remove-target-bound-identifier","swap-reported-miner-identity",
         ],"source-bound adversarial controls changed")
    return p


def _safe(role:str,action:str,*,evidence:int=0,original:bool=False)->dict:
    require(role in ROLES and (action in DISPLAYS or action==DENY),
            "source relevance verdict not in frozen set")
    return {
        "role":role,"action":action,
        "app_consumption":"DISPLAY_UNVERIFIED_PACKAGE_ADVISORY_REFERENCES_ONLY"
            if action=="DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES"
            else "DENY_UNSCOPED_OR_UNVERIFIED_SECURITY_INFORMATION",
        "target":"npm:lodash@4.17.15",
        "reported_advisory_reference_count":evidence,
        "original_external_paid_capture":bool(original),
        "no_auto_security_clearance":True,
        "not_independent_advisory_accuracy_gold":True,
        "not_fair_same_intent_comparison":True,
        "registered_network_evaluator":False,
        "real_miner_ranking_improved":False,
    }


def _expected_request(role:str,request:object)->bool:
    if not isinstance(request,dict):return False
    if role=="canonical_routed_off_target":
        return request=={
            "intent":"SECURITY_REVIEW_GENERAL",
            "params":{"target":"npm package lodash version 4.17.15"},
        }
    if request.get("method")!="GET" or request.get("endpoint")!="/query":
        return False
    payload=request.get("payload")
    if role=="direct_deps_dev_ghsa":
        return payload=={"system":"npm","pkg":"lodash","ver":"4.17.15"}
    if role=="direct_deps_dev_version":
        return payload=={"pkg":"lodash","ver":"4.17.15"}
    return False


def classify(role:str,request:object,body:object)->dict:
    """Local relevance only: exact package identity, never vulnerability truth."""
    require(role in ROLES,"unknown public original provider context")
    if not _expected_request(role,request) or not isinstance(body,dict):
        return _safe(role,DENY)
    if (str(body.get("miner_id"))!={
            "canonical_routed_off_target":"77003",
            "direct_deps_dev_ghsa":"190048",
            "direct_deps_dev_version":"77010"}[role]
            or body.get("result_shape")!="raw"):
        return _safe(role,DENY)
    result=body.get("result")
    if role=="canonical_routed_off_target":
        # An unscoped 100-advisory feed provides no evidence that any row
        # applies to npm lodash@4.17.15, even with keyword padding.
        if not isinstance(result,list) or len(result)!=100 or not all(
                isinstance(x,dict) and
                type(x.get("ghsa_id")) is str and
                ADVISORY.fullmatch(x["ghsa_id"]) is not None
                for x in result):
            return _safe(role,DENY)
        return _safe(role,"DENY_UNSCOPED_SECURITY_ADVICE",evidence=100)
    if not isinstance(result,dict):
        return _safe(role,DENY)
    if role=="direct_deps_dev_ghsa":
        if result.get("versionKey")!={
             "name":"lodash","system":"NPM","version":"4.17.15"}:
            return _safe(role,DENY)
        refs=result.get("advisoryKeys")
        if not isinstance(refs,list) or len(refs)!=6 or not all(
                isinstance(x,dict) and
                type(x.get("id")) is str and
                ADVISORY.fullmatch(x["id"]) is not None for x in refs):
            return _safe(role,DENY)
        if len({x["id"] for x in refs})!=6:
            return _safe(role,DENY)
        return _safe(role,"DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES",evidence=6)
    package=result.get("package")
    version=result.get("version")
    if not isinstance(package,dict) or package.get("name")!="lodash" or \
            package.get("system")!="NPM" or not isinstance(version,dict) or \
            version.get("version")!="4.17.15":
        return _safe(role,DENY)
    advisories=version.get("advisories")
    if not isinstance(advisories,list) or len(advisories)!=6:
        return _safe(role,DENY)
    aliases=[]
    for item in advisories:
        if not isinstance(item,dict) or item.get("source")!="OSV":
            return _safe(role,DENY)
        names=item.get("aliases")
        if not isinstance(names,list) or len(names)==0 or not all(
                isinstance(name,str) and CVE.fullmatch(name) is not None
                for name in names):
            return _safe(role,DENY)
        aliases+=names
    if len(set(aliases))!=len(aliases):
        return _safe(role,DENY)
    return _safe(role,"DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES",evidence=6)


def _original_docs(*,root:Path=ROOT,download=fetch_bytes)->list[dict]:
    p=frozen(root)
    originals=[]
    for spec in p["original_immutable_third_party_fixtures"]:
        url=SOURCE_BASE+spec["path"]
        raw=download(url)
        require(isinstance(raw,bytes) and 0<len(raw)<=2_500_000
                and git_blob_sha(raw)==spec["git_blob_sha1"],
                "actual original third-party public Git source differs from frozen Git blob")
        obj=json.loads(raw)
        require(isinstance(obj,dict)
                and obj.get("paid") is True
                and obj.get("charged") is True
                and obj.get("ok") is True
                and obj.get("status")==200
                and isinstance(obj.get("payment"),dict)
                and obj["payment"].get("success") is True,
                "original paid-flagged external public report body changed")
        body=obj.get("body")
        receipt=obj.get("receipt")
        require(isinstance(body,dict) and isinstance(receipt,dict)
                and isinstance(body.get("signal_hash"),str)
                and HASH64.fullmatch(body["signal_hash"]) is not None
                and isinstance(receipt.get("receipt_hash"),str)
                and HASH64.fullmatch(receipt["receipt_hash"]) is not None
                and str(body.get("miner_id"))==spec["reported_miner_id"]
                and receipt.get("intent")==spec["reported_receipt_intent"],
                "original external public miner identity, signal or receipt claim mismatch")
        require(_expected_request(spec["role"],obj.get("request")),
                "original public source request not for the same exact npm package/version")
        check=classify(spec["role"],obj["request"],body)
        require(check["action"]==spec["expected_display_action"]
                and check["reported_advisory_reference_count"]==
                     spec["expected_advisory_count"],
                "original real outcome differs from precommitted task-relevance expectation")
        originals.append({
            "spec":spec,"document":obj,"verdict":check,
            "uri":VIEW_BASE+spec["path"],
        })
    require(len(originals)==3 and len({
            x["document"]["body"]["miner_id"] for x in originals})==3,
            "original target-matched public reported Miner IDs not three distinct identifiers")
    return originals


def _mutate(role:str,obj:dict,mutation:str)->dict:
    copied=deepcopy(obj)
    request=copied["request"]
    if mutation=="change-request-package":
        if role=="canonical_routed_off_target":
            request["params"]["target"]=request["params"]["target"].replace(
                "lodash","leftpad")
        else:request["payload"]["pkg"]="leftpad"
    elif mutation=="change-request-version":
        if role=="canonical_routed_off_target":
            request["params"]["target"]=request["params"]["target"].replace(
                "4.17.15","4.18.1")
        else:request["payload"]["ver"]="4.18.1"
    elif mutation=="remove-target-bound-identifier":
        if role=="direct_deps_dev_ghsa":
            copied["body"]["result"]["versionKey"]=None
        elif role=="direct_deps_dev_version":
            copied["body"]["result"]["package"]=None
        else:
            copied["body"]["result"][0]["ghsa_id"]="fabricated"
    elif mutation=="swap-reported-miner-identity":
        copied["body"]["miner_id"]="999999"
    else:raise TargetRelevanceError("mutation not in frozen protocol")
    return copied


def study(*,root:Path=ROOT,download=fetch_bytes)->dict:
    p=frozen(root)
    originals=_original_docs(root=root,download=download)
    results=[]
    negative=[]
    for entry in originals:
        spec=entry["spec"]
        action=entry["verdict"]
        original=entry["document"]
        results.append({
            "role":spec["role"],
            "source_git_blob_sha1":spec["git_blob_sha1"],
            "original_external_source_url":entry["uri"],
            "original_reported_miner_id":spec["reported_miner_id"],
            "source_git_blob_authenticated":True,
            "reported_paid_and_http200":True,
            "original_signal_hash_present":True,
            "original_receipt_hash_present":True,
            "original_recorded_intent":spec["reported_receipt_intent"],
            "request_channel":spec["request_channel"],
            "target_same_semantics":True,
            "action":action["action"],
            "source_bound_unverified_advisory_reference_count":
                action["reported_advisory_reference_count"]
                if action["action"].startswith("DISPLAY") else 0,
            "original_unscoped_advisory_count":
                action["reported_advisory_reference_count"]
                if action["action"].startswith("DENY") else 0,
            "not_network_rank_comparable":True,
        })
        for mutation in p["local_synthetic_mutation_types"]:
            altered=_mutate(spec["role"],original,mutation)
            outcome=classify(spec["role"],altered["request"],altered["body"])
            require(outcome["action"]!=
                    "DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES",
                    "original public provider identity, package or response mutation bypassed the source relevance gate")
            negative.append({
                "original_role":spec["role"],"mutation":mutation,
                "decision":"DENY","target_bound_display_allowed":False,
                "constructed_from_pinned_public_original_not_external_observation":True,
            })
    require(len(results)==3 and len(negative)==12 and
            Counter(r["action"] for r in results)=={
                "DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES":2,
                "DENY_UNSCOPED_SECURITY_ADVICE":1,
            },"three original external and twelve constructed decisions incomplete")
    return {
        "schema_version":1,"status":ST_REPORT,
        "original_protocol_git_blob_sha1":FROZEN_BLOB,
        "original_public_git_repository":ORIGINAL_SOURCE_REPO,
        "original_public_git_revision":ORIGINAL_SOURCE_COMMIT,
        "original_genuine_paid_flagged_third_party_captures":3,
        "actual_reported_distinct_miner_ids":3,
        "all_three_semantic_target":"npm:lodash@4.17.15",
        "original_canonical_routed_responses":1,
        "original_direct_get_query_responses":2,
        "byte_identical_requests_across_three":False,
        "same_protocol_intent_across_three":False,
        "independent_miner_ownership_verified":False,
        "original_public_reported_paid_flags_not_chain_settlement_verified":True,
        "actual_original_target_bound_package_references_displayable":2,
        "actual_original_unscoped_advisory_feed_denied":1,
        "original_unsafe_http_paid_accept_all_baseline_allowed":3,
        "local_synthetic_adversarial_controls":12,
        "local_synthetic_adversarial_controls_denied":12,
        "independent_appsec_accuracy_gold":0,
        "independent_reference_advisory_correctness_audited":False,
        "global_telegraph_ranking_improved":False,
        "fair_same_canonical_intent_miner_comparison":False,
        "registered_evaluator":False,
        "original_full_public_paid_response_bodies_republished":False,
        "actual_paid_requests_by_falsum":0,
        "independent_adoption_of_falsum":False,
        "official_h2_submitted":False,
        "original_observational_results":results,
        "constructed_anti_bypass_controls":negative,
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Audit three exact original paid-flagged public lodash Miner outputs: semantic target only, different protocols, NO ranking proof")
    parser.add_argument("--out",type=Path,required=True)
    a=parser.parse_args(argv)
    try:
        require(a.out.suffix==".json" and not a.out.exists() and
                not a.out.is_symlink(),"source proof aggregate output must be fresh write-once JSON")
        report=study()
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open("x",encoding="utf-8") as f:
            json.dump(report,f,indent=2,sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status":report["status"],
            "real_original_distinct_miner_ids":report["actual_reported_distinct_miner_ids"],
            "package_specific_original_displays":report["actual_original_target_bound_package_references_displayable"],
            "original_unscoped_advisory_feed_denied":report["actual_original_unscoped_advisory_feed_denied"],
            "local_synthetic_controls_denied":report["local_synthetic_adversarial_controls_denied"],
            "all_requests_same_canonical_intent":False,
            "real_miner_ranking_improved":False,
        },sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,AssertionError,
            TargetRelevanceError) as error:
        parser.exit(1,"PHASE5X ORIGINAL THIRD-PARTY PUBLIC RELEVANCE AUDIT FAILED CLOSED: "+
                    str(error)[:260]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
