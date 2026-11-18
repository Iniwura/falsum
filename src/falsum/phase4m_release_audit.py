"""Phase 4M: fail-closed offline release-integrity audit, not a model-quality award.

This rechecks the genuine frozen model/source ledger, and prevents stale or
contradictory H2 submission claims. It cannot independently confirm Anjoman
account ownership, expert adjudication, third-party use, or official entry.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re

from .phase4i_evidence_comparison import report as real_source_comparison

ROOT = Path(__file__).resolve().parents[2]
DOCUMENTS = (
    "README.md",
    "docs/H2_FINAL_ENTRY_DRAFT.md",
    "docs/H2_EVALUATORS_JUDGE_PACK.md",
)
STATUS = "PHASE4M_RECORDED_MODEL_AND_PUBLIC_CLAIMS_AUDIT_NOT_RELEASE_APPROVAL"
FIRST_PERSON_PLURAL = re.compile(r"\b(?:we|our|we've|we're)\b", re.IGNORECASE)
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class ReleaseAuditError(ValueError):
    pass


def check(ok: bool, message: str) -> None:
    if not ok:
        raise ReleaseAuditError(message)


def inspect_public_docs(contents: dict[str, str], root: Path | None = None) -> dict:
    check(isinstance(contents, dict) and set(contents) == set(DOCUMENTS),
          "missing or extra final-research document")
    for path, text in contents.items():
        check(isinstance(text, str) and len(text) > 100,
              "empty/missing public document " + path)
        check(FIRST_PERSON_PLURAL.search(text) is None,
              "collective authorship in solo project document " + path)
    entry = contents["docs/H2_FINAL_ENTRY_DRAFT.md"]
    judge = contents["docs/H2_EVALUATORS_JUDGE_PACK.md"]
    readme = contents["README.md"]
    check("**STATUS: NOT SUBMITTED.**" in entry,
          "not-submitted entry gate omitted")
    check("Sunday, November 22" in entry and "November 22" in judge
          and "November 22" in readme,
          "internal completion target missing or stale")
    check("December 1, 2026" in entry and "December 1, 2026" in judge,
          "official H2 deadline missing")
    check("zero rows" in entry.lower() or "zero records" in entry.lower(),
          "unresolved public contributor zero-row result omitted")
    check("zero rows" in judge.lower() and "0 rows" in readme.lower(),
          "public contributor address discrepancy not retained consistently")
    for document in (entry, judge, readme):
        low = document.lower()
        check("20" in document and "eligible" in low,
              "historical account status must be preserved with its actual caveats")
        check("unresolved" in low and "maintainer" in low,
              "public row discrepancy and maintainer acceptance must remain distinguished")
        check("5/8" in document and "1/4" in document and "4/8" in document,
              "source-fix model and constant baseline evidence missing")
        check("not" in low and ("trained" in low or "adapter" in low),
              "unproven model improvement may be promoted")
    latest_markers = {
        "docs/H2_FINAL_ENTRY_DRAFT.md": "**November 17 live evidence update:**",
        "docs/H2_EVALUATORS_JUDGE_PACK.md": "**November 17 network audit:**",
        "README.md": "**Latest read-only network check (November 17):**",
    }
    for path, marker in latest_markers.items():
        document = contents[path]
        check(document.count(marker) == 1,
              "missing or duplicated latest network audit section " + path)
        latest = document.split(marker, 1)[1].split("\n\n", 1)[0].lower()
        check("332" in latest and "10" in latest and "unknown" in latest,
              "latest live 17 November public pool and UNKNOWN contributor state omitted")
        check(("http error" in latest or "httperror" in latest)
              and ("network-wide" in latest or "intent-wide" in latest),
              "current contributor HTTP failure must not be conflated with entire Intent pool")
    # Later evidence supersedes the earlier mistaken-address assumption,
    # without erasing the original November 14/17 readback events.
    corrected_markers = {
        "README.md": "**Corrected network verification (November 18):**",
        "docs/H2_FINAL_ENTRY_DRAFT.md": "**November 18 verified account-address correction:**",
        "docs/H2_EVALUATORS_JUDGE_PACK.md": "**November 18 account reconciliation:**",
    }
    for path, marker in corrected_markers.items():
        document = contents[path]
        check(document.count(marker) == 1,
              "Nov 18 corrected Privy wallet source disclosure missing")
        excerpt = document.split(marker, 1)[1].split("\n\n", 1)[0].lower()
        check("20" in excerpt and "eligible" in excerpt
              and "privy" in excerpt and ("0" in excerpt or "zero" in excerpt),
              "Phase 4N confirmed 20 eligible on correct wallet must not disappear")
        check("maintainer" in excerpt and ("not" in excerpt or "unresolved" in excerpt),
              "Phase 4N row eligibility cannot be presented as bounty acceptance")
    check("phase 4l" in entry.lower() and "phase 4l" in judge.lower()
          and "phase 4l" in readme.lower(),
          "external PR Guard evidence omitted or miscontextualized")
    local_links_checked = 0
    if root is not None:
        root_abs = root.resolve()
        for path, text in contents.items():
            document_dir = (root_abs / path).parent
            for match in LINK.finditer(text):
                target = match.group(1).strip().split("#", 1)[0].strip()
                if (not target or target.startswith(("http://", "https://",
                        "mailto:", "tel:", "#", "data:"))):
                    continue
                if target.startswith("/"):
                    check((root_abs / target.lstrip("/")).is_file(),
                          "broken root-relative documentation link in " + path)
                else:
                    dest = (document_dir / target).resolve()
                    check(dest.is_relative_to(root_abs) and dest.is_file(),
                          "broken or unsafe relative documentation link in " + path +
                          ": " + target[:120])
                local_links_checked += 1
    return {
        "documents_checked": list(DOCUMENTS),
        "local_document_links_verified": local_links_checked,
        "solo_builder_public_copy": True,
        "historical_20_ui_vs_zero_live_node_discrepancy_disclosed": True,
        "correct_wallet_20_eligible_and_wrong_wallet_zero_documented_with_source": True,
        "unproven_model_improvement_claim_blocked": True,
        "official_entry_not_falsely_marked_submitted": True,
    }


def run(root: Path = ROOT) -> dict:
    documents = {p: (root / p).read_text(encoding="utf-8") for p in DOCUMENTS}
    copy = inspect_public_docs(documents, root)
    # This loads the exact original model checkpoint score ledger, validates all
    # 16 float32 bits and frozen upstream source identities. No network, no retrain.
    result = real_source_comparison(root)
    for key, expected in {
        "real_official_foundation_score_recording": True,
        "original_quarantined_lora": True,
        "current_live_inference": False,
        "model_trained_or_improved_in_phase4i": False,
        "model_registered": False,
        "independent_expert_gold_labels": 0,
        "model_quality_improvement_established": False,
        "model_source_author_matches": 5,
        "model_complete_reversals": 1,
        "constant_A_matches": 4,
        "constant_B_matches": 4,
        "source_aware_oracle_is_hardcoded_from_author_hypotheses": True,
        "project_count": 4,
        "case_count": 8,
        "model_f32_inputs": 16,
    }.items():
        check(result.get(key) == expected and type(result.get(key)) is type(expected),
              "actual frozen source-model evidence drift: " + key)
    groups = result.get("groups")
    check(isinstance(groups, list) and len(groups) == 4
          and all(len(g.get("revisions", [])) == 2 for g in groups),
          "missing or malformed fixed-source cases")
    check(sum(bool(v["matches_researcher_source_expectation"])
              for g in groups for v in g["revisions"]) == 5,
          "per-revision decisions contradict observed aggregate")
    check(sum(bool(g["complete_source_consistent_reversal"])
              for g in groups) == 1,
          "per-source revisions contradict observed model reversal")
    return {
        "schema_version": 1,
        "status": STATUS,
        "methodology_verified": {
            "frozen_real_original_model_bits": 16,
            "public_source_projects": 4,
            "researcher_interpreted_source_matches": 5,
            "source_conditions": 8,
            "complete_correct_parent_to_fix_reversals": 1,
            "total_parent_to_fix_pairs": 4,
            "always_A_source_matches": 4,
            "always_B_source_matches": 4,
            "new_model_or_adapter": False,
            "expert_independent_gold_labels": 0,
            "quality_improvement_proven": False,
        },
        "publication_claims_checked": copy,
        "external_review_source_validation_separate_phase4l": True,
        "source_grounded_36_checks_is_not_model_accuracy": True,
        "qualification_blockers_still_unverified": [
            "corrected_contributor_address_clarification_acknowledged_by_maintainer",
            "user_privy_wallet_ownership_cryptographically_verified_if_required",
            "public_h2_registration_and_bounties_star",
            "final_2_to_5_minute_real_demo_or_accessible_equivalent",
            "actual_official_h2_submission_and_receipt",
        ],
        "independent_quality_gaps": [
            "source_based_appsec_expert_adjudication",
            "sealed_unseen_project_and_failure_type_evaluation",
            "measured_trained_evaluator_improvement_against_fair_baselines",
            "verified_external_application_adoption",
        ],
        "released_ready": False,
        "notes": (
            "Passing this offline audit verifies immutable old-model score evidence "
            "and truthful public copy, NOT current Anjoman identity, model accuracy, "
            "network acceptance, reviewer expertise, third-party adoption or award "
            "eligibility. Do not turn these null/unverified gates into zero or success."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evidence-based release integrity audit; never certifies readiness")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        check(not args.out.exists() and not args.out.is_symlink(),
              "refuse overwrite")
        result = run()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(result, out, indent=2, sort_keys=True)
            out.write("\n")
        print(json.dumps({
            "status": result["status"],
            "original_model_matches": "5/8",
            "complete_source_sensitive_reversals": "1/4",
            "constant_A_B": "4/8 each",
            "independent_gold_labels": 0,
            "ready_to_submit": False,
            "remaining_qualification_gates": result["qualification_blockers_still_unverified"],
        }, indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        p.exit(1, "FALSUM PHASE 4M RELEASE AUDIT FAILED (" + type(exc).__name__ +
               "): " + str(exc)[:180] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
