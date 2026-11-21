"""Phase 5Y: actual independent GitHub-reviewed advisory version evidence.

Cross-check two authentic original third-party reported-paid Miner output lists
for npm lodash@4.17.15 against SIX separately maintained GitHub-reviewed
advisory JSON files at an immutable pinned original Git commit. This evaluates
ONLY package/version applicability among the reported references, not recall,
severity, exploitability, human AppSec certification or Telegraph rankings.

Every original byte (six reviewed facts, two outside provider captures) must
match its frozen Git blob. No original third-party response body is republished.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

from .phase4l_external_receipt_evidence import git_blob_sha, SOURCE_BASE, fetch_bytes
from .phase5m_real_source_sensitive_model import ROOT
from .phase5x_three_real_miner_target_relevance import (
    _original_docs, _expected_request,
)

LOCK="data/phase5y-original-reviewed-lodash-six-advisory-protocol.json"
LOCK_GIT_BLOB_SHA1="ed0e5c40d918dbc46e8a7e58eeb0a225cfaef237"
ADVISORY_COMMIT="76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
ADVISORY_REPO="github/advisory-database"
REVIEWED_PREFIX=f"https://raw.githubusercontent.com/{ADVISORY_REPO}/{ADVISORY_COMMIT}/"
VIEW_PREFIX=f"https://github.com/{ADVISORY_REPO}/blob/{ADVISORY_COMMIT}/"
STATUS="PHASE5Y_AUTHENTIC_REVIEWED_ADVISORY_VERSION_APPLICABILITY_ON_TWO_ORIGINAL_PAID_MINER_CAPTURES"
ROLES=("direct_deps_dev_ghsa","direct_deps_dev_version")
TARGET={"ecosystem":"npm","package":"lodash","version":"4.17.15"}
VERSION=re.compile(r"^(?:0|[0-9]+\.[0-9]+\.[0-9]+)$")
SHA1=re.compile(r"^[0-9a-f]{40}$")
GHSA=re.compile(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")
CVE=re.compile(r"^CVE-\d{4}-\d{4,8}$")


class VersionEvidenceError(ValueError): pass


def need(ok:bool,reason:str)->None:
    if not ok: raise VersionEvidenceError(reason)


def frozen(root:Path=ROOT)->dict:
    path=root/LOCK
    raw=path.read_bytes()
    need(git_blob_sha(raw)==LOCK_GIT_BLOB_SHA1,
         "pre-implementation original reviewed-advisory protocol was changed")
    p=json.loads(raw)
    need(isinstance(p,dict)
         and p.get("schema_version")==1
         and p.get("status")==
           "PHASE5Y_INDEPENDENT_GITHUB_REVIEWED_ADVISORY_VERSION_APPLICABILITY_FROZEN_BEFORE_IMPLEMENTATION"
         and p.get("target")==TARGET
         and p.get("primary_reference_source")==ADVISORY_REPO
         and p.get("primary_reference_original_git_commit")==ADVISORY_COMMIT
         and p.get("original_external_provider_source")=="anvithagowda098/pr-guard"
         and p.get("original_provider_captures_git_commit")=="99d2e3c93890a8fc083947bde4f21217516b7a5f"
         and p.get("original_advisory_id_count")==6
         and p.get("actual_distinct_recorded_miner_ids")==2
         and p.get("actual_raw_reported_advisory_references")==12
         and p.get("verified_distinct_applicable_advisories_count")==5
         and p.get("verified_distinct_inapplicable_advisories_count")==1
         and p.get("expected_12_original_provider_reference_matches")=={
            "applicable":10,"inapplicable":2}
         and p.get("identified_version_inapplicable_advisory")==
            "GHSA-f23m-r3pf-42rh"
         and p.get("identified_version_inapplicable_cve")=="CVE-2026-2950"
         and p.get("fixed_exclusive_semver_rule") is True
         and p.get("last_affected_inclusive_semver_rule") is True
         and p.get("independent_source_maintainer_distinct_from_published_provider_app") is True
         and p.get("qualified_human_appsec_gold_count")==0
         and p.get("does_not_establish_advisory_recall_or_completeness") is True
         and p.get("recorded_provider_paid_status_not_independently_settled") is True
         and p.get("both_direct_receipts_intent")=="SECURITY_REVIEW"
         and p.get("true_same_canonical_intent_comparison") is False
         and p.get("independent_provider_ownership_verified") is False
         and p.get("no_hidden_private_evaluation_source") is True
         and p.get("no_registered_network_evaluator") is True
         and p.get("no_actual_network_rank_change") is True
         and p.get("no_new_paid_requests_by_falsum") is True
         and p.get("no_external_falsum_adoption_claim") is True
         and p.get("no_official_h2_submission") is True
         and p.get("exact_historical_github_sources_required") is True,
         "original facts or critical adversarial/accuracy scope changed")
    originals=p.get("original_advisory_sources")
    miners=p.get("original_provider_captures")
    need(isinstance(originals,list) and len(originals)==6
         and isinstance(miners,list) and len(miners)==2
         and [x.get("role") for x in miners]==list(ROLES)
         and [x.get("reported_miner_id") for x in miners]==["190048","77010"],
         "six reviewed advisory references and two original Miner identities required")
    need(len({x.get("id") for x in originals})==6
         and len({x.get("original_cve_alias") for x in originals})==6
         and len({x.get("original_git_blob_sha1") for x in originals})==6,
         "original reviewed reference IDs/aliases/sha not distinct")
    for entry in originals:
        need(isinstance(entry,dict) and
             GHSA.fullmatch(str(entry.get("id",""))) is not None and
             CVE.fullmatch(str(entry.get("original_cve_alias",""))) is not None and
             SHA1.fullmatch(str(entry.get("original_git_blob_sha1",""))) is not None and
             all(VERSION.fullmatch(str(entry.get(k,""))) is not None
                 for k in ("original_lodash_range_introduced",
                           "original_lodash_range_fixed_exclusive")) and
             entry.get("source_path","").startswith("advisories/github-reviewed/") and
             ".." not in entry["source_path"],"unsupported reviewed Git advisory reference")
    for entry in miners:
        need(SHA1.fullmatch(str(entry.get("original_git_blob_sha1",""))) is not None and
             entry.get("intent_on_original_receipt")=="SECURITY_REVIEW" and
             entry.get("direct_request_channel")=="GET /query" and
             entry.get("path","").startswith("test/fixtures/miner-responses/"),
             "original outside paid Miner source not Git-pinned")
    return p


def semver(value:str)->tuple[int,int,int]:
    """Strict simple numeric versions used by these frozen original records."""
    need(type(value) is str and VERSION.fullmatch(value) is not None,
         "only numeric three-part historical npm semver or zero boundary allowed")
    if value=="0":return (0,0,0)
    parts=tuple(map(int,value.split(".")))
    need(all(n<=999999 for n in parts),"version numeric component oversized")
    return parts


def interval(version:str,events:list)->bool:
    """Version applicability for a reviewed ECOSYSTEM interval.

    'introduced' inclusive; 'fixed' exclusive; 'last_affected' inclusive.
    Reject exotic or ambiguous event series rather than guessing.
    """
    need(isinstance(events,list) and len(events)==2 and
         all(isinstance(x,dict) and len(x)==1 for x in events),
         "reviewed source contains unsupported or ambiguous interval sequence")
    start,end=events
    need(set(start)=={"introduced"} and
         set(end) in ({"fixed"},{"last_affected"}),
         "only original introduced/fixed or last_affected reviewed interval supported")
    lower=semver(start["introduced"])
    upper=semver(next(iter(end.values())))
    target=semver(version)
    need(lower<=upper,"reviewed version range boundaries inverted")
    return lower<=target and (target<upper if "fixed" in end else target<=upper)


def advisory_applies(document:dict, *,package:str="lodash",ecosystem:str="npm",
                     version:str="4.17.15")->tuple[bool,dict]:
    need(isinstance(document,dict) and
         isinstance(document.get("affected"),list),
         "GitHub-reviewed advisory missing structured affected-package ranges")
    matching=[p for p in document["affected"]
              if isinstance(p,dict) and
              p.get("package")=={"name":package,"ecosystem":ecosystem}]
    need(len(matching)==1,"ambiguous or missing EXACT npm lodash package entry")
    ranges=matching[0].get("ranges")
    need(isinstance(ranges,list) and len(ranges)==1 and
         isinstance(ranges[0],dict) and ranges[0].get("type")=="ECOSYSTEM",
         "unsupported upstream reviewed affected version range")
    events=ranges[0].get("events")
    decision=interval(version,events)
    # Do not infer applicability from a similarly named lodash.* subpackage.
    boundaries={"introduced":events[0]["introduced"],
                "upper_exclusive_or_last_affected":next(iter(events[1].values())),
                "upper_type":next(iter(events[1]))}
    return decision,boundaries


def _fetch_reviewed(url:str)->bytes:
    need(url.startswith(REVIEWED_PREFIX) and ".." not in url,
         "only frozen original GitHub-reviewed advisory source allowed")
    request=Request(url,headers={"Accept":"application/json",
                                 "User-Agent":"FALSUM-review-version-evidence/1.0"})
    with urlopen(request,timeout=35) as response:
        need(response.status==200 and response.geturl()==url,
             "original reviewed Git source missing or redirected")
        raw=response.read(200_001)
    need(0<len(raw)<=200_000,"original reviewed advisory file missing/oversized")
    return raw


def load_reviewed(*,root:Path=ROOT,download=_fetch_reviewed)->tuple[list[dict],dict]:
    policy=frozen(root)
    rows=[]
    ids={}
    for spec in policy["original_advisory_sources"]:
        raw=download(REVIEWED_PREFIX+spec["source_path"])
        need(type(raw) is bytes and 0<len(raw)<=200_000 and
             git_blob_sha(raw)==spec["original_git_blob_sha1"],
             "reviewed upstream advisory original complete Git blob SHA1 differs")
        document=json.loads(raw.decode("utf-8","strict"))
        need(isinstance(document,dict)
             and document.get("id")==spec["id"]
             and isinstance(document.get("aliases"),list)
             and spec["original_cve_alias"] in document["aliases"]
             and GHSA.fullmatch(document["id"]) is not None,
             "reviewed upstream Git-source advisory identity/alias changed")
        applies,boundaries=advisory_applies(document)
        need(boundaries["introduced"]==spec["original_lodash_range_introduced"]
             and boundaries["upper_exclusive_or_last_affected"]==
                    spec["original_lodash_range_fixed_exclusive"]
             and boundaries["upper_type"]=="fixed"
             and applies is spec["expected_applicable_to_npm_lodash_4_17_15"],
             "independent original reviewed version interval contradicts pre-committed fact")
        row={
            "ghsa_id":spec["id"],"cve_alias":spec["original_cve_alias"],
            "reviewed_original_git_blob_sha1":spec["original_git_blob_sha1"],
            "reviewed_original_source_url":
                VIEW_PREFIX+spec["source_path"],
            "exact_package_ecosystem":"npm/lodash",
            "reviewed_introduced_inclusive":boundaries["introduced"],
            "reviewed_fixed_exclusive":boundaries["upper_exclusive_or_last_affected"],
            "original_reference_applicable_to_lodash_4_17_15":applies,
            "not_universal_security_assurance":True,
        }
        ids[spec["id"]]=row
        rows.append(row)
    need(len(rows)==6 and sum(x["original_reference_applicable_to_lodash_4_17_15"]
                             for x in rows)==5,
         "six externally reviewed affected/version reference outcomes missing")
    return rows,ids


def _actual_provider_items(entry:dict,policy:dict)->tuple[str,list[str]]:
    spec=entry["spec"]
    role=spec["role"]
    need(role in ROLES,"unknown external direct Miner role")
    frozen_record=next(x for x in policy["original_provider_captures"]
                       if x["role"]==role)
    need(spec["path"]==frozen_record["path"] and
         spec["git_blob_sha1"]==frozen_record["original_git_blob_sha1"] and
         spec["reported_miner_id"]==frozen_record["reported_miner_id"],
         "original external provider source blob/role changed from preregistration")
    document=entry["document"]
    need(_expected_request(role,document.get("request")) and
         document.get("status")==200 and document.get("paid") is True
         and document.get("charged") is True,
         "original outside Miner response not recorded paid request for exact target")
    body=document["body"]
    result=body["result"]
    if role=="direct_deps_dev_ghsa":
        need(result.get("versionKey")=={
            "name":"lodash","system":"NPM","version":"4.17.15"},
            "original GHSA Miner answer not exactly about npm lodash 4.17.15")
        refs=result.get("advisoryKeys")
        need(isinstance(refs,list) and len(refs)==6,
             "original direct GHSA Miner advisory list no longer has six")
        identifiers=[x.get("id") for x in refs if isinstance(x,dict)]
    else:
        need(result.get("package")=={"name":"lodash","system":"NPM"}
             and isinstance(result.get("version"),dict)
             and result["version"].get("version")=="4.17.15",
             "original OSV Miner answer not exactly about npm lodash 4.17.15")
        refs=result["version"].get("advisories")
        need(isinstance(refs,list) and len(refs)==6,
             "original direct OSV Miner advisory list no longer has six")
        identifiers=[]
        for item in refs:
            need(isinstance(item,dict) and item.get("source")=="OSV"
                 and isinstance(item.get("aliases"),list)
                 and len(item["aliases"])==1,
                 "original OSV response has unknown multi-identifier semantics")
            identifiers.append(item["aliases"][0])
    need(len(identifiers)==6 and len(set(identifiers))==6
         and all(isinstance(s,str) for s in identifiers),
         "original outside Miner advisory identifiers duplicate or missing")
    return role,identifiers


def study(*,root:Path=ROOT,download_reviewed=_fetch_reviewed,
          download_external=fetch_bytes)->dict:
    policy=frozen(root)
    original_references,by_id=load_reviewed(root=root,download=download_reviewed)
    originals=_original_docs(root=root,download=download_external)
    chosen={e["spec"]["role"]:e for e in originals if e["spec"]["role"] in ROLES}
    need(set(chosen)==set(ROLES),"two original public outside Miner sources not authenticated")
    cve_to_ghsa={v["cve_alias"]:v["ghsa_id"] for v in original_references}
    original_decisions=[]
    per_provider=[]
    all_counts=Counter()
    for role in ROLES:
        source=chosen[role]
        role,claimed=_actual_provider_items(source,policy)
        rows=[]
        for identifier in claimed:
            ghsa=(identifier if role=="direct_deps_dev_ghsa"
                  else cve_to_ghsa.get(identifier))
            need(ghsa in by_id,
                 "original provider advisory not found in independent reviewed six-article source set")
            reference=by_id[ghsa]
            applies=reference["original_reference_applicable_to_lodash_4_17_15"]
            action=("DISPLAY_VERSION_APPLICABLE_UNVERIFIED_REFERENCE"
                    if applies else "REJECT_VERSION_INAPPLICABLE_REFERENCE")
            all_counts["applicable" if applies else "inapplicable"]+=1
            item={
                "original_reported_miner_id":source["spec"]["reported_miner_id"],
                "original_provider_source_git_blob_sha1":source["spec"]["git_blob_sha1"],
                "provider_original_request_channel":"GET /query",
                "original_reported_receipt_intent":"SECURITY_REVIEW",
                "target":"npm:lodash@4.17.15",
                "original_provider_reported_identifier":identifier,
                "independent_reviewed_ghsa_id":ghsa,
                "independent_reviewed_cve_alias":reference["cve_alias"],
                "reviewed_original_source_url":reference["reviewed_original_source_url"],
                "reviewed_original_source_git_blob_sha1":
                    reference["reviewed_original_git_blob_sha1"],
                "reviewed_original_introduced":reference["reviewed_introduced_inclusive"],
                "reviewed_original_fixed":reference["reviewed_fixed_exclusive"],
                "reviewed_reference_package_version_applicable":applies,
                "application_gate_action":action,
                "reference_is_separately_maintained_not_expert_gold":True,
                "independent_provider_ownership_verified":False,
            }
            rows.append(item)
            original_decisions.append(item)
        need(len(rows)==6 and sum(x["reviewed_reference_package_version_applicable"]
                                 for x in rows)==5,"original direct Miner 5/6 version applicability unexpectedly changed")
        per_provider.append({
            "original_reported_miner_id":source["spec"]["reported_miner_id"],
            "original_external_source_git_blob_sha1":source["spec"]["git_blob_sha1"],
            "original_external_public_source_url":source["uri"],
            "original_recorded_paid_http200":True,
            "original_receipt_intent":"SECURITY_REVIEW",
            "reported_advisories":len(rows),
            "reviewed_version_applicable_reported_advisories":5,
            "reviewed_version_inapplicable_reported_advisories":1,
            "reported_references_missed_by_naive_paid_acceptance":1,
            "version_applicability_fraction_among_reported_references":"5/6",
            "does_not_measure_advisory_recall_or_completeness":True,
        })
    need(all_counts=={"applicable":10,"inapplicable":2}
         and len(original_decisions)==12
         and [x["original_reported_miner_id"] for x in per_provider]==["190048","77010"]
         and {x["independent_reviewed_ghsa_id"] for x in original_decisions
              if not x["reviewed_reference_package_version_applicable"]}==
                    {"GHSA-f23m-r3pf-42rh"},
         "original independent reviewed version False Positive mismatch")
    return {
        "schema_version":1,"status":STATUS,
        "frozen_preimplementation_git_blob_sha1":LOCK_GIT_BLOB_SHA1,
        "independent_reviewed_original_source_repo":ADVISORY_REPO,
        "independent_reviewed_original_git_revision":ADVISORY_COMMIT,
        "original_third_party_provider_capture_repo":"anvithagowda098/pr-guard",
        "original_external_provider_capture_git_revision":
            "99d2e3c93890a8fc083947bde4f21217516b7a5f",
        "target":"npm:lodash@4.17.15",
        "independent_reviewed_advisory_files_full_git_blob_verified":6,
        "original_paid_status_provider_capture_git_blobs_verified":2,
        "reported_distinct_miner_ids":["190048","77010"],
        "original_recorded_provider_receipt_intents":["SECURITY_REVIEW","SECURITY_REVIEW"],
        "all_requests_same_exact_canonical_intent":False,
        "byte_identical_original_provider_requests":False,
        "reported_original_paid_flags_no_independent_settlement":True,
        "original_reported_advisory_references":12,
        "independent_reviewed_version_applicable_references":10,
        "independent_reviewed_version_inapplicable_references":2,
        "distinct_version_inapplicable_ghsa_ids":["GHSA-f23m-r3pf-42rh"],
        "distinct_version_inapplicable_cve_aliases":["CVE-2026-2950"],
        "distinct_independent_reviewed_advisories":6,
        "distinct_version_applicable_advisories":5,
        "distinct_version_inapplicable_advisories":1,
        "version_inapplicable_reported_reference_fraction":"1/6 per provider",
        "naive_http_200_paid_accepted_all_references":12,
        "evidence_bound_gate_allowed_reference_display_only":10,
        "evidence_bound_gate_denied_version_inapplicable_references":2,
        "both_miners_might_share_original_upstream_sources":True,
        "independent_human_appsec_gold":0,
        "model_accuracy_or_training_improvement_proven":False,
        "advisory_recall_or_completeness_proven":False,
        "same_canonical_intent_ranking_comparison":False,
        "telegraph_network_rank_improvement":False,
        "registered_network_evaluator":False,
        "new_paid_telegraph_requests":0,
        "falsum_adopted_by_third_party":False,
        "original_full_external_response_bodies_republished":False,
        "official_h2_entry_submitted":False,
        "real_original_provider_rows":per_provider,
        "authenticated_independent_reviewed_advisory_sources":original_references,
        "original_provider_reference_decisions":original_decisions,
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(
        description="Original external Miner reported lodash advisories compared against immutable independent reviewed affected-version ranges")
    parser.add_argument("--out",type=Path,required=True)
    a=parser.parse_args(argv)
    try:
        need(a.out.suffix==".json" and not a.out.exists() and
             not a.out.is_symlink(),"only fresh write-once original evidence report allowed")
        report=study()
        a.out.parent.mkdir(parents=True,exist_ok=True)
        with a.out.open("x",encoding="utf-8") as f:
            json.dump(report,f,indent=2,sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status":report["status"],
            "genuine_original_reference_files":6,
            "original_public_provider_paid_captures":2,
            "version_applicable_claims":report["independent_reviewed_version_applicable_references"],
            "version_inapplicable_claims":report["independent_reviewed_version_inapplicable_references"],
            "distinct_false_positive_advisories":1,
            "same_canonical_intent_comparison":False,
            "certified_expert_gold":0,
        },sort_keys=True))
        return 0
    except (OSError,UnicodeError,TypeError,ValueError,KeyError,
            AssertionError,VersionEvidenceError) as exc:
        parser.exit(1,"PHASE5Y ACTUAL ORIGINAL INDEPENDENT REVIEWED SOURCE PROOF FAILED CLOSED: "+
                    str(exc)[:270]+"\n")


if __name__=="__main__":raise SystemExit(main())
