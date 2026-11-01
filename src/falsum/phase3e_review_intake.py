"""Phase 3E public review intake: attribution claims are NOT accepted expert labels.

The protocol deliberately separates a reviewer's self-reported preference from
independent verification. A GitHub comment URL alone does not prove expertise,
an external reviewer, evidence correctness, or network eligibility. Every
review remains quarantined pending a separate documented human verification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from .phase2w_proof_gate import ProofError,_canonical
from .phase3e_review_packets import STATUS as PACKET_STATUS

STATUS="PHASE3E_REVIEW_INTAKE_SELF_REPORTED_NOT_VERIFIED_OR_NETWORK_ELIGIBLE"
LOGIN=re.compile(r"[A-Za-z\d](?:[A-Za-z\d-]{0,37}[A-Za-z\d])?\Z")
COMMENT_URL=re.compile(r"https://github\.com/Iniwura/falsum/issues/\d+#issuecomment-\d+\Z")
REVIEW_FIELDS={
    "packet_id","source_git_blob_sha1","reviewer_github_login",
    "review_comment_url","candidate_preference","explanation",
    "version_evidence_status","runtime_evidence_status",
    "independent_reviewer_self_attested",
}
CASE_LIMIT=5


def receive(bundle:dict,submissions:dict)->dict:
    if (not isinstance(bundle,dict) or bundle.get("status")!=PACKET_STATUS
        or bundle.get("network_eligible") is not False
        or bundle.get("accepted_training_pairs")!=0
        or bundle.get("independent_human_labels")!=0
        or bundle.get("actual_third_party_apps_executed")!=0
        or not isinstance(bundle.get("packets"),list)
        or len(bundle["packets"])!=CASE_LIMIT):
        raise ProofError("Phase3E must consume unadjudicated source-verified review packets")
    packets={p["packet_id"]:p for p in bundle["packets"]}
    if len(packets)!=CASE_LIMIT or any(
        p.get("label_status")!="NOT_INDEPENDENTLY_ADJUDICATED"
        or p.get("official_network_eligible") is not False
        or p.get("training_eligible") is not False
        or p.get("reviewer_preference") is not None
        or p.get("confirmed_exploit") is not False
        for p in bundle["packets"]
    ):
        raise ProofError("already reviewed or fraudulent upstream review packet")
    if (not isinstance(submissions,dict) or set(submissions)!={"schema_version","status","packet_bundle_sha256","reviews"}
        or type(submissions["schema_version"]) is not int
        or submissions["schema_version"]!=1
        or submissions["status"]!="UNVERIFIED_PUBLIC_REVIEW_SUBMISSIONS"
        or submissions["packet_bundle_sha256"]!=hashlib.sha256(_canonical(bundle)).hexdigest()):
        raise ProofError("review references a different or tampered upstream packet bundle")
    reviews=submissions["reviews"]
    if not isinstance(reviews,list) or len(reviews)>50:
        raise ProofError("unbounded self-reported reviewer material")
    seen=set()
    items=[]
    for rev in reviews:
        if (not isinstance(rev,dict) or set(rev)!=REVIEW_FIELDS
            or rev["packet_id"] not in packets
            or rev["source_git_blob_sha1"]!=packets[rev["packet_id"]]["source"]["git_blob_sha1"]
            or not isinstance(rev["reviewer_github_login"],str)
            or not LOGIN.fullmatch(rev["reviewer_github_login"])
            or rev["reviewer_github_login"].lower()=="iniwura"
            or not isinstance(rev["review_comment_url"],str)
            or not COMMENT_URL.fullmatch(rev["review_comment_url"])
            or rev["candidate_preference"] not in ("A","B","ABSTAIN")
            or rev["version_evidence_status"] not in ("UNKNOWN","DECLARED_ONLY","INSTALLED_VERSION_INDEPENDENTLY_CHECKED_CLAIM")
            or rev["runtime_evidence_status"] not in ("UNKNOWN","SOURCE_SYNTAX_ONLY","REGISTERED_ROUTE_INDEPENDENTLY_CHECKED_CLAIM")
            or rev["independent_reviewer_self_attested"] is not True
            or not isinstance(rev["explanation"],str)
            or not 70<=len(rev["explanation"])<=3000
            or "\x00" in rev["explanation"]):
            raise ProofError("invalid or ungrounded self-reported external review")
        unique=(rev["packet_id"],rev["reviewer_github_login"].lower())
        if unique in seen:
            raise ProofError("duplicate claimed reviewer for same packet")
        seen.add(unique)
        items.append({
            "packet_id":rev["packet_id"],
            "source_git_blob_sha1":rev["source_git_blob_sha1"],
            "claimed_reviewer":rev["reviewer_github_login"],
            "unverified_public_comment":rev["review_comment_url"],
            "claimed_preference":rev["candidate_preference"],
            "claimed_version_evidence":rev["version_evidence_status"],
            "claimed_runtime_evidence":rev["runtime_evidence_status"],
            "submitted_explanation_sha256":hashlib.sha256(rev["explanation"].encode()).hexdigest(),
            "github_comment_author_verified":False,
            "reviewer_independence_verified":False,
            "appsec_expertise_verified":False,
            "underlying_security_facts_verified":False,
            "accepted_ground_truth":False,
            "training_eligible":False,
        })
    counts={id_:sum(x["packet_id"]==id_ for x in items) for id_ in sorted(packets)}
    return {
        "schema_version":1,"status":STATUS,"research_only":True,
        "source_review_packets":CASE_LIMIT,
        "self_reported_review_records":len(items),
        "self_reported_reviewers_unique":len({x["claimed_reviewer"].lower() for x in items}),
        "claimed_reviews_per_packet":counts,
        "unresolved_review_conflicts":sum(len({
            x["claimed_preference"] for x in items if x["packet_id"]==p
        })>1 for p in counts),
        "review_claims":items,
        "verified_independent_human_labels":0,
        "accepted_training_pairs":0,"network_eligible":False,
        "evaluator_registered":False,
        "need_external_github_attribution_check":len(items)>0,
        "need_independent_domain_expert_adjudication":True,
        "warning":"A self-attested GitHub link and explanation are NOT evidence of independent expertise or accurate label. This tool never counts any review as independent/eligible, and never trains or registers an evaluator."
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Receive independently claimed review feedback but NEVER auto-approve it")
    parser.add_argument("--packets",required=True,type=Path)
    parser.add_argument("--reviews",required=True,type=Path)
    parser.add_argument("--out",required=True,type=Path)
    args=parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ProofError("will not overwrite existing review report")
        bundle=json.loads(args.packets.read_text())
        reviews=json.loads(args.reviews.read_text())
        result=receive(bundle,reviews)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(result))
        print(json.dumps({
            "claimed_reviews":result["self_reported_review_records"],
            "verified_expert_labels":0,"network_eligible":False
        },indent=2))
        return 0
    except (ProofError,ValueError,TypeError,KeyError,OSError) as exc:
        parser.exit(1,f"FALSUM UNVERIFIED HUMAN REVIEW INTAKE ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
