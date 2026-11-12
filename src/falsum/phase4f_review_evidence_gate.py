"""Phase 4F: honest independent-review evidence census and benchmark release gate.

Input 1: Phase 4E's seven source-verifiable cases and reversed A/B displays.
Input 2: Phase 3W's actual public GitHub issue-form review claim audit.

A real GitHub issue can establish a claim and a citation format. It can NEVER
automatically establish professional expertise, source correctness, gold labels,
model improvement or network-eligible evaluation material.

Without *separately and independently verified* adjudications, all reported
quality metrics stay null and both the evaluator and training gates stay closed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from .phase4e_counterbalanced_reviews import STATUS as PACK_STATUS

STATUS = "PHASE4F_REVIEW_EVIDENCE_REGISTER_UNADJUDICATED_QUALITY_WITHHELD"
REVIEW_STATUS = "PHASE3W_GITHUB_REVIEW_CLAIMS_UNADJUDICATED_NO_LABELS"
GITHUB_ISSUE = re.compile(r"^https://github\.com/Iniwura/falsum/issues/([1-9][0-9]*)$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")


class GateError(ValueError):
    pass


def require(condition: bool, error: str) -> None:
    if not condition:
        raise GateError(error)


def hash_json(value: dict) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                   ).encode("utf-8")
    ).hexdigest()


def validate_pack(pack: dict) -> dict[str, dict]:
    require(isinstance(pack, dict)
            and pack.get("schema_version") == 1
            and pack.get("status") == PACK_STATUS
            and pack.get("intent") == "SECURITY_REVIEW_GENERAL"
            and pack.get("source_backed_unique_review_cases") == 7
            and pack.get("counterbalanced_presentation_count") == 14
            and pack.get("distinct_upstream_repositories") == 7
            and pack.get("security_families") == 7
            and pack.get("independent_gold_labels") == 0
            and pack.get("new_eligible_anjoman_rows") == 0
            and pack.get("registered_evaluator") is False
            and pack.get("training_allowed") is False
            and pack.get("general_model_accuracy_measured") is False
            and pack.get("not_a_blind_holdout") is True
            and pack.get("not_full_application_exploitation") is True,
            "missing Phase 4E source or research-only contract")
    cases = pack.get("cases")
    require(isinstance(cases, list) and len(cases) == 7,
            "expected seven independently identifiable source-fix cases")
    seen, repositories, families = set(), set(), set()
    ordered = {}
    for row in cases:
        require(isinstance(row, dict), "case is not an object")
        ident, repo, family = (
            row.get("case_id"), row.get("upstream_repository"),
            row.get("security_family"))
        require(isinstance(ident, str) and 2 < len(ident) < 90
                and ident not in seen, "duplicate or invalid case identity")
        require(isinstance(repo, str) and repo not in repositories
                and isinstance(family, str) and family not in families,
                "duplicate repository/family, not a project-separated review pack")
        seen.add(ident); repositories.add(repo); families.add(family)
        require(row.get("independently_approved_answer") is None
                and row.get("independent_expert_reviewer_verified") is False
                and row.get("training_authorized") is False
                and row.get("network_eligible") is False
                and row.get("live_application_exploit_verified") is False,
                "research author answers cannot become gold labels")
        variants = row.get("two_counterbalanced_presentations")
        require(isinstance(variants, list) and len(variants) == 2
                and variants[0].get("orientation") == "original"
                and variants[1].get("orientation") == "swapped",
                "counterbalanced views absent")
        left = variants[0].get("reviewer_display_answers")
        right = variants[1].get("reviewer_display_answers")
        require(isinstance(left, list) and isinstance(right, list)
                and len(left) == len(right) == 2
                and [a.get("display_position") for a in left] == ["A","B"]
                and [a.get("display_position") for a in right] == ["A","B"],
                "position variants invalid")
        for variant in variants:
            require(variant.get("preference_label") is None
                    and variant.get("expert_review_verified") is False
                    and variant.get("score_by_model") is None,
                    "no pretrained or authored label in displayed variants")
        for i, j in ((0,1),(1,0)):
            a, b = left[i], right[j]
            require(a.get("text") == b.get("text")
                    and a.get("candidate_text_sha256") == b.get("candidate_text_sha256")
                    and isinstance(a.get("text"), str)
                    and hashlib.sha256(a["text"].encode()).hexdigest()
                        == a["candidate_text_sha256"],
                    "position change modified answer text or its SHA")
        ordered[ident] = row
    return ordered


def validate_review_audit(review: dict, case_index: dict[str, dict]) -> dict[str, list[dict]]:
    require(isinstance(review, dict)
            and review.get("schema_version") == 1
            and review.get("status") == REVIEW_STATUS
            and review.get("intent") == "SECURITY_REVIEW_GENERAL"
            and review.get("review_sources") == 7
            and review.get("independent_expert_certified_labels") == 0
            and review.get("accepted_training_pairs") == 0
            and review.get("new_eligible_anjoman_rows") == 0
            and review.get("trainable_preference_pairs") == []
            and review.get("registered_evaluator") is False
            and review.get("network_eligible") is False
            and review.get("security_accuracy_certified") is False,
            "unverified claims or review intake promoted into accepted gold")
    claims, coverage, rejected = (
        review.get("claims"), review.get("coverage"), review.get("rejected"))
    require(isinstance(claims, list) and isinstance(coverage, list)
            and isinstance(rejected, list)
            and review.get("public_format_valid_claims") == len(claims)
            and review.get("public_rejected_form_claims") == len(rejected)
            and len(coverage) == 7,
            "review claim census totals inconsistent")
    require(review.get("github_issues_fetched_live") in (True, False)
            and type(review["github_issues_fetched_live"]) is bool,
            "must disclose live versus fixture review source")
    by_case = {case_id: [] for case_id in case_index}
    unique_issues, distinct_authors = set(), set()
    for claim in claims:
        require(isinstance(claim, dict), "non-object reviewer claim")
        ident = claim.get("case_id")
        author = claim.get("github_author")
        issue = claim.get("issue_number")
        url = claim.get("issue_url")
        match = GITHUB_ISSUE.fullmatch(url) if isinstance(url,str) else None
        require(ident in by_case
                and isinstance(author, str) and author.casefold() != "iniwura"
                and type(issue) is int and issue > 0
                and match is not None and int(match.group(1)) == issue
                and issue not in unique_issues
                and claim.get("preference_claim") in ("A","B","ABSTAIN")
                and claim.get("source_test_and_advisory_links_format_checked") is True
                and claim.get("source_claim_correctness_verified") is False
                and claim.get("independent_security_expertise_verified") is False
                and claim.get("reviewer_authorship_independently_verified") is False
                and claim.get("training_label_accepted") is False
                and isinstance(claim.get("submitted_body_sha256"),str)
                and HEX64.fullmatch(claim["submitted_body_sha256"]),
                "invalid reviewer attribution or false independent adjudication")
        unique_issues.add(issue)
        pair = (ident,author.casefold())
        require(pair not in distinct_authors, "same account counted twice for one case")
        distinct_authors.add(pair)
        by_case[ident].append(claim)
    coverage_index={}
    for row in coverage:
        require(isinstance(row,dict) and row.get("case_id") in by_case
                and row["case_id"] not in coverage_index,
                "missing/duplicate census case")
        ident = row["case_id"]
        claims_here=by_case[ident]
        observed=sorted(set(c["preference_claim"] for c in claims_here))
        require(row.get("format_valid_distinct_github_claims")==len(claims_here)
                and row.get("positions_claimed")==observed
                and row.get("unresolved_disagreement")== (len(observed)>1)
                and row.get("independently_certified_security_labels")==0,
                "review census disagrees with observed public claims")
        coverage_index[ident]=row
    require(set(coverage_index) == set(by_case), "missing case census row")
    return by_case


def build(pack: dict, review: dict) -> dict:
    source_index=validate_pack(pack)
    by_case=validate_review_audit(review,source_index)
    rows=[]
    total_format_valid=0
    for ident,source in source_index.items():
        claims=by_case[ident]
        total_format_valid += len(claims)
        positions=sorted(set(x["preference_claim"] for x in claims))
        rows.append({
            "case_id": ident,
            "security_family": source["security_family"],
            "upstream_repository": source["upstream_repository"],
            "source_fix_commit": source["source_fix_commit"],
            "source_fix_commit_url": source["source_fix_commit_url"],
            "regression_test_file_url": source["regression_test_file_url"],
            "original_and_swapped_answer_texts_verified": True,
            "format_valid_public_claim_count":len(claims),
            "published_unverified_opinions": positions,
            "published_review_issue_urls": sorted(x["issue_url"] for x in claims),
            "any_disagreement_requires_human_resolution":len(positions)>1,
            "independently_adjudicated_expert_gold_label":None,
            "gold_label_status":"WITHHELD_PENDING_INDEPENDENT_REVIEW",
            "model_predictions_available":False,
            "project_disjoint_sealed_test_case":False,
            "trainable_or_network_eligible":False,
        })
    require(total_format_valid==review["public_format_valid_claims"],
            "public issue count changed during aggregation")
    return {
        "schema_version":1,
        "status": STATUS,
        "scope":"PUBLIC_CODE_BEHAVIOR_SOURCE_REVIEW_NOT_GHSA_VERSION_LOOKUP",
        "intent":"SECURITY_REVIEW_GENERAL",
        "source_pack_sha256":hash_json(pack),
        "public_review_intake_sha256":hash_json(review),
        "review_intake_fetched_live":review["github_issues_fetched_live"],
        "source_verified_case_count":len(rows),
        "distinct_upstream_project_count":7,
        "counterbalanced_display_conditions":14,
        "total_public_format_valid_claims":total_format_valid,
        "public_claims_rejected_by_intake":review["public_rejected_form_claims"],
        "independent_expert_adjudications_accepted":0,
        "gold_labeled_cases":0,
        "actual_model_scored_cases_on_this_review_pack":0,
        "source_grounded_model_accuracy":None,
        "constant_A_baseline_accuracy":None,
        "constant_B_baseline_accuracy":None,
        "constant_ABSTAIN_baseline_accuracy":None,
        "model_position_invariance_score":None,
        "relative_evaluator_improvement":None,
        "lower_bound_confidence_interval":None,
        "not_a_sealed_project_disjoint_holdout":True,
        "no_model_registration_or_training":True,
        "new_anjoman_eligible_pairs":0,
        "release_ready_to_claim_measured_improvement":False,
        "release_blockers":[
            "Independent qualified AppSec adjudication absent; source-cited GitHub opinions cannot self-certify",
            "No genuinely sealed, project-disjoint test set prepared and locked before model development",
            "No real Foundation inference predictions for these adjudicated cases",
            "No fair shared-label baseline comparison can be computed without gold labels",
        ],
        "cases":rows,
        "notice":(
            "An authenticated GitHub issue is an unverified reviewer claim, NOT "
            "an independently vetted expert label. The absence of labels or real "
            "model scores means benchmark accuracy and improvement remain null, "
            "not zero and not 100 percent. Seven cases, fourteen presentation "
            "conditions; no model-quality or winning-performance claim."
        ),
    }


def main(argv=None)->int:
    p=argparse.ArgumentParser(description="Fail-closed real-review census and benchmark readiness gate")
    p.add_argument("--source-pack",required=True,type=Path)
    p.add_argument("--review-audit",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink(),
                "refuse overwrite of an existing public review census")
        source=json.loads(args.source_pack.read_text(encoding="utf-8"))
        review=json.loads(args.review_audit.read_text(encoding="utf-8"))
        report=build(source,review)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:report[k] for k in (
            "status","source_verified_case_count","total_public_format_valid_claims",
            "independent_expert_adjudications_accepted","gold_labeled_cases",
            "actual_model_scored_cases_on_this_review_pack",
            "relative_evaluator_improvement","release_ready_to_claim_measured_improvement")},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError) as exc:
        p.exit(1,"FALSUM REVIEWED BENCHMARK BLOCKED: "+str(exc)+"\n")


if __name__=="__main__":
    raise SystemExit(main())
