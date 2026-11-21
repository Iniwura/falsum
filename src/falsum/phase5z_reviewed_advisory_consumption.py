"""Fail-closed application display of original reviewed package/version references.

Three real external reported-paid Git captures + six independently maintained
GitHub-reviewed advisories; none imply independent AppSec gold, fair network
rank, payment settlement, external adoption or automatic security clearance.
Local caller inputs are explicitly not authenticated original Miner captures.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from .phase4l_external_receipt_evidence import git_blob_sha,fetch_bytes
from .phase5m_real_source_sensitive_model import ROOT,sha
from .phase5x_three_real_miner_target_relevance import (
    frozen as source_frozen,_original_docs as original_docs,
    classify as relevance,ROLES,TARGET)
from .phase5y_original_reviewed_version_applicability import (
    frozen as reviewed_frozen,load_reviewed,semver,_fetch_reviewed)

LOCK="data/phase5z-frozen-app-consumption-protocol.json"
LOCK_BLOB="46b42a68360e5f9011a2d60abd25db81176a4a73"
STATUS="PHASE5Z_ORIGINAL_THREE_MINER_SAFE_REFERENCE_CONSUMPTION"
LOCAL_STATUS="PHASE5Z_UNVERIFIED_CALLER_INPUT_LOCAL_REVIEWED_REFERENCE_CONSUMPTION"
ALLOW="DISPLAY_REVIEWED_VERSION_APPLICABLE_REFERENCES_ONLY"
DENY="DENY_UNVERIFIED_OR_UNSCOPED_ADVICE"
NO_APPROVAL="MATCHES_REVIEWED_PACKAGE_VERSION_RANGE_NOT_SECURITY_CLEARANCE"
BAD_GHSA="GHSA-f23m-r3pf-42rh"

class ConsumptionError(ValueError): pass

def need(ok:bool,reason:str)->None:
    if not ok:raise ConsumptionError(reason)

def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK).read_bytes()
    need(git_blob_sha(raw)==LOCK_BLOB,"original application protocol changed after freeze")
    p=json.loads(raw)
    limits=p.get("explicit_limits",{})
    need(p.get("status")==
         "PHASE5Z_FROZEN_VERSION_REVIEWED_ADVISORY_REFERENCE_APP_CONSUMPTION_PROTOCOL_BEFORE_IMPLEMENTATION"
         and p.get("schema_version")==1
         and p.get("target")==TARGET and p.get("original_roles")==list(ROLES)
         and p.get("original_provider_miner_ids")==["77003","190048","77010"],
         "frozen interface drift")
    need(p.get("original_phase5x_git_blob")=="227b91ab42688ac4a02a95633ba3556d3ff8b84f"
         and p.get("original_phase5y_git_blob")=="ed0e5c40d918dbc46e8a7e58eeb0a225cfaef237"
         and p.get("original_external_published_records")==3
         and p.get("original_reviewed_advisory_records")==6
         and p.get("expected_total_display_only_reference_instances")==10
         and p.get("expected_total_version_inapplicable_reference_instances_rejected")==2
         and p.get("expected_distinct_version_inapplicable_ghsa")==[BAD_GHSA]
         and all(limits.get(k) is True for k in (
          "not_same_canonical_intent_competition","not_byte_identical_requests",
          "not_independent_provider_ownership","payment_settlement_unverified",
          "no_new_paid_calls","no_registered_telegraph_evaluator",
          "not_general_package_range_verifier","no_full_advisory_recall",
          "no_human_expert_gold","not_automated_security_approval",
          "no_independent_adoption","no_official_h2_entry",
          "previously_known_public_cases_not_hidden_holdout")),
         "original observation limit or expected outcomes drifted")
    expected=p.get("expected_original_application_decisions",{})
    need(expected.get("canonical_routed_off_target")=={
          "action":"DENY_UNSCOPED_ADVISORY_FEED",
          "advisories_displayable":0,"advisories_rejected":100}
         and all(expected.get(x)=={
          "action":ALLOW,"advisories_displayable":5,"advisories_rejected":1}
          for x in ROLES[1:]),
         "original expected independent-source decisions altered")
    need(source_frozen(root)["question_target"]==TARGET and
         reviewed_frozen(root)["target"]==TARGET,
         "original source-bound studies no longer match target")
    return p

def reviewed_index(rows:list[dict],*,root:Path=ROOT)->tuple[dict,dict]:
    need(isinstance(rows,list) and len(rows)==6,
         "six independent reviewed original advisories required")
    policy=reviewed_frozen(root)
    source_spec={x["id"]:x for x in policy["original_advisory_sources"]}
    ghsa={}
    cves={}
    for row in rows:
        need(isinstance(row,dict) and row.get("ghsa_id") in source_spec,
             "unknown reviewed original GHSA source")
        spec=source_spec[row["ghsa_id"]]
        need(row.get("reviewed_original_git_blob_sha1")==spec["original_git_blob_sha1"]
             and row.get("cve_alias")==spec["original_cve_alias"]
             and row.get("exact_package_ecosystem")=="npm/lodash"
             and row.get("reviewed_original_source_url")==
               "https://github.com/github/advisory-database/blob/76955defc62d048f8f7cc68bc39a2f6dd1899ebe/"+spec["source_path"]
             and row.get("not_universal_security_assurance") is True
             and row.get("reviewed_introduced_inclusive")==spec["original_lodash_range_introduced"]
             and row.get("reviewed_fixed_exclusive")==spec["original_lodash_range_fixed_exclusive"]
             and type(row.get("original_reference_applicable_to_lodash_4_17_15")) is bool
             and row["original_reference_applicable_to_lodash_4_17_15"]==
               (semver(row["reviewed_introduced_inclusive"])<=semver("4.17.15")<
                semver(row["reviewed_fixed_exclusive"]))
             and row["ghsa_id"] not in ghsa and row["cve_alias"] not in cves,
             "reviewed original advisory source identity, numeric interval or duplicate failed")
        ghsa[row["ghsa_id"]]=row
        cves[row["cve_alias"]]=row
    need(set(ghsa)==set(source_spec)
         and sum(r["original_reference_applicable_to_lodash_4_17_15"] for r in rows)==5,
         "independent reviewed six-source population incomplete")
    return ghsa,cves

def deny(role:str,reason:str,original:bool=False)->dict:
    return {"role":role,"target":"npm:lodash@4.17.15","action":DENY,
            "reason":reason,"display_references":[],"suppressed_references":[],
            "display_count":0,"suppressed_count":0,
            "original_external_capture_git_verified":original,
            "independent_reviewed_git_source_required":True,
            "no_automatic_security_clearance":True,
            "same_canonical_intent_network_ranking_proved":False}

def consume(role:str,request:object,body:object,reviewed:list[dict],
            *,root:Path=ROOT)->dict:
    frozen(root)
    need(role in ROLES,"unsupported original provider family")
    ghsa,cves=reviewed_index(reviewed,root=root)
    # Caller-supplied provenance, overrides or extra request-envelope fields
    # must not be interpreted as proof that a public Miner capture is original.
    valid_keys=({"intent","params"} if role=="canonical_routed_off_target"
                else {"method","endpoint","payload"})
    if not isinstance(request,dict) or set(request)!=valid_keys:
        return deny(role,"UNKNOWN_OR_FORGED_REQUEST_ENVELOPE_FIELDS",False)
    if not isinstance(body,dict) or "original_external_capture_git_verified" in body:
        return deny(role,"UNTRUSTED_OR_FORGED_RESPONSE_PROVENANCE",False)
    result=relevance(role,request,body)
    if role=="canonical_routed_off_target":
        return deny(role,"UNSCOPED_100_ADVISORY_FEED_NOT_PACKAGE_BOUND",
                    False)
    if result["action"]!="DISPLAY_TARGET_BOUND_UNVERIFIED_ADVISORY_REFERENCES":
        return deny(role,"ORIGINAL_PACKAGE_TARGET_OR_PROVIDER_ID_NOT_BOUND",
                    False)
    raw=(body["result"]["advisoryKeys"] if role=="direct_deps_dev_ghsa"
         else body["result"]["version"]["advisories"])
    refs=ghsa if role=="direct_deps_dev_ghsa" else cves
    choices=[]
    for item in raw:
        if not isinstance(item,dict):
            return deny(role,"MALFORMED_OR_UNKNOWN_ADVISORY",
                        False)
        if role=="direct_deps_dev_ghsa":
            key=item.get("id")
        else:
            aliases=item.get("aliases")
            if not isinstance(aliases,list) or len(aliases)!=1:
                return deny(role,"UNKNOWN_OR_AMBIGUOUS_CVE",
                            False)
            key=aliases[0]
        if not isinstance(key,str) or key not in refs:
            return deny(role,"NOT_IN_INDEPENDENT_REVIEWED_SOURCE_SET",
                        False)
        choices.append((key,refs[key]))
    if len(choices)!=6 or len({a for a,b in choices})!=6:
        return deny(role,"DUPLICATE_OR_INCOMPLETE_REFERENCE_SET",
                    False)
    visible=[]
    suppressed=[]
    for identifier,record in choices:
        sanitized={
           "original_provider_reference_id":identifier,
           "verified_ghsa_id":record["ghsa_id"],
           "verified_cve_alias":record["cve_alias"],
           "reviewed_original_source":record["reviewed_original_source_url"],
           "reviewed_original_git_blob_sha1":record["reviewed_original_git_blob_sha1"],
           "introduced_inclusive":record["reviewed_introduced_inclusive"],
           "fixed_exclusive":record["reviewed_fixed_exclusive"],
           "package":"npm:lodash@4.17.15",
           "reference_meaning":NO_APPROVAL,
        }
        (visible if record["original_reference_applicable_to_lodash_4_17_15"]
         else suppressed).append(sanitized)
    need(len(visible)==5 and len(suppressed)==1 and
         {x["verified_ghsa_id"] for x in suppressed}=={BAD_GHSA},
         "original reviewed source range population disagrees with original capture")
    return {
       "role":role,"target":"npm:lodash@4.17.15","action":ALLOW,
       "reason":"INDEPENDENT_REVIEWED_EXACT_PACKAGE_VERSION_REFS_FOR_DISPLAY_ONLY",
       "display_references":visible,"suppressed_references":suppressed,
       "display_count":len(visible),"suppressed_count":len(suppressed),
       "original_external_capture_git_verified":False,
       "independent_reviewed_git_source_required":True,
       "no_automatic_security_clearance":True,
       "same_canonical_intent_network_ranking_proved":False,
    }

def study(*,root:Path=ROOT,fetch_original=fetch_bytes,
          fetch_reviewed=_fetch_reviewed)->dict:
    frozen(root)
    sources,_=load_reviewed(root=root,download=fetch_reviewed)
    originals=original_docs(root=root,download=fetch_original)
    need(len(originals)==3 and [o["spec"]["role"] for o in originals]==list(ROLES),
         "original externally published three real Miner Git blobs missing")
    manifest=[]
    for src in originals:
        role=src["spec"]["role"]
        original=src["document"]
        output=consume(role,original["request"],original["body"],sources,
                       root=root)
        # Attach original provenance ONLY after the original external
        # Git blob hash checker has independently validated this capture.
        output["original_external_capture_git_verified"]=True
        expected=frozen(root)["expected_original_application_decisions"][role]
        need(output["action"]==(DENY if role==ROLES[0] else ALLOW)
             and output["display_count"]==expected["advisories_displayable"]
             and output["suppressed_count"]==(0 if role==ROLES[0] else 1),
             "actual original outside provider sanitized outputs diverge from preregistration")
        manifest.append({
          "reported_original_miner_id":src["spec"]["reported_miner_id"],
          "original_external_git_blob_sha1":src["spec"]["git_blob_sha1"],
          "original_source_url":src["uri"],
          "recorded_paid_status":True,
          "original_receipt_intent":src["spec"]["reported_receipt_intent"],
          "request_sha256":sha(json.dumps(original["request"],sort_keys=True).encode()),
          "display_only_security_reference_decision":output,
        })
    need(sum(x["display_only_security_reference_decision"]["display_count"]
             for x in manifest)==10 and
         sum(x["display_only_security_reference_decision"]["suppressed_count"]
             for x in manifest)==2 and
         manifest[0]["display_only_security_reference_decision"]["action"]==DENY,
         "original 3-real-source display-only app decision result changed")
    return {
       "schema_version":1,"status":STATUS,
       "frozen_original_application_git_blob_sha1":LOCK_BLOB,
       "original_external_git_authenticated_miner_captures":3,
       "original_reviewed_advisory_git_verified_sources":6,
       "original_real_unscoped_advisory_feed_denied":1,
       "original_direct_provider_outputs_reference_filtered":2,
       "original_direct_provider_references":12,
       "original_reviewed_version_applicable_display_only_references":10,
       "original_version_inapplicable_suppressed_references":2,
       "original_distinct_advisories_with_version_false_positive":1,
       "all_requests_same_canonical_intent":False,
       "original_miner_ownership_independently_verified":False,
       "independent_paid_settlement_verified":False,
       "independent_appsec_gold":0,
       "external_adoption_proven":False,
       "network_evaluator_registered":False,
       "network_ranking_improvement_proven":False,
       "falsum_new_paid_calls":0,
       "entire_original_third_party_body_republished":False,
       "official_hackathon_submission":False,
       "public_original_source_decisions":manifest,
    }

def _bounded(path:Path)->dict:
    need(path.is_file() and not path.is_symlink() and
         0<path.stat().st_size<=2_500_000,"local user JSON must be regular bounded file")
    obj=json.loads(path.read_bytes())
    need(isinstance(obj,dict),"local input JSON must be object")
    return obj

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Original independently reviewed version-bound reference display gate")
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--role",choices=ROLES)
    p.add_argument("--request-json",type=Path)
    p.add_argument("--response-json",type=Path)
    args=p.parse_args(argv)
    try:
        need(args.out.suffix==".json" and not args.out.exists() and
             not args.out.is_symlink(),"output must be fresh write-once JSON")
        local=any(x is not None for x in
                  (args.role,args.request_json,args.response_json))
        if local:
            need(args.role and args.request_json and args.response_json,
                 "local request requires role, request-json, response-json")
            original_reviewed,_=load_reviewed()
            output=consume(args.role,_bounded(args.request_json),
                           _bounded(args.response_json),original_reviewed)
            result={
                "schema_version":1,"status":LOCAL_STATUS,
                "local_user_supplied_not_original_capture":True,
                "original_external_capture_git_verified":False,
                "reviewed_source_original_git_authentication":True,
                "security_reference_consumption":output,
                "does_not_echo_original_input":True,
                "no_paid_requests":True,
                "not_registered_network_evaluator":True,
                "not_security_clearance":True,
            }
        else:result=study()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open("x",encoding="utf-8") as f:
            json.dump(result,f,sort_keys=True,indent=2)
            f.write("\n")
        print(json.dumps({"status":result["status"],
            "original_external_sources":result.get(
                "original_external_git_authenticated_miner_captures"),
            "display_only":result.get(
                "original_reviewed_version_applicable_display_only_references",
                result.get("security_reference_consumption",{}).get("display_count",0)),
            "suppressed":result.get(
                "original_version_inapplicable_suppressed_references",
                result.get("security_reference_consumption",{}).get("suppressed_count",0)),
            "registered_network_evaluator":False},sort_keys=True))
        return 0
    except (OSError,ValueError,UnicodeError,TypeError,KeyError) as e:
        p.exit(1,"PHASE5Z FAIL-CLOSED APP REFERENCE CONSUMPTION: "+
               str(e)[:280]+"\n")

if __name__=="__main__":
    raise SystemExit(main())
