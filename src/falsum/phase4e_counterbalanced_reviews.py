"""Phase 4E: genuinely source-verified, position-counterbalanced AppSec review pack.

The source is Phase 3F's *live reverified* eight historical Git commits and
source/test patches.  Seven distinct public vulnerability families are presented
to outside reviewers with original and reversed A/B display orders.  These are
14 presentation conditions of SEVEN unreviewed cases, not 14 accepted rows.

NEVER auto-promote an author's preference to a human-reviewed label or release
the previously failed Telegraph model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from .phase3f_multifamily_material import PINS, STATUS as SOURCE_STATUS

STATUS = "PHASE4E_SOURCE_PINNED_COUNTERBALANCED_SEVEN_FAMILY_REVIEW_PACK_UNADJUDICATED"
MIN_SHA = re.compile(r"^[a-f0-9]{64}$")
MIN_BLOB = re.compile(r"^[a-f0-9]{40}$")
REVIEW_FORM = "https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml"
RUBRIC = (
    "Does the exact published source and regression test support the stated security precondition?",
    "Which deployment facts (attacker control, affected version, configuration and reachability) remain unknown?",
    "Does either candidate overclaim exploitability or remediation safety?",
    "Do not infer a deployed exploit merely from a published upstream fix.",
    "Choose by the text and primary evidence, not by A/B position; ABSTAIN if neither answer is justified.",
)


class ReviewPackError(ValueError):
    pass


def must(ok: bool, message: str):
    if not ok:
        raise ReviewPackError(message)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_source(source: dict) -> list[dict]:
    must(isinstance(source, dict)
         and source.get("schema_version") == 1
         and source.get("status") == SOURCE_STATUS
         and source.get("intent") == "SECURITY_REVIEW_GENERAL"
         and source.get("external_source_revisions_verified") == 8
         and source.get("external_source_and_test_file_blob_pairs_verified") == 8
         and source.get("review_cases") == 7
         and source.get("distinct_security_families") == 7
         and source.get("research_only") is True
         and source.get("fresh_project_holdout_reused") is False
         and source.get("independent_human_labels") == 0
         and source.get("accepted_training_pairs") == 0
         and source.get("network_eligible") is False
         and source.get("registered_evaluator") is False
         and source.get("full_application_execution") is False
         and source.get("actual_production_exploits_verified") == 0,
         "Phase 3F original verified evidence or no-label contract was altered")
    for name in ("original_queue_sha256","training_queue_sha256","catalog_sha256"):
        must(isinstance(source.get(name), str) and MIN_SHA.fullmatch(source[name]),
             "missing pinned input catalogue identity")
    rows = source.get("review_packets")
    must(isinstance(rows, list) and len(rows) == len(PINS) == 7,
         "source cases missing")
    must(len({p["repository"] for p in rows}) == 7
         and len({p["security_family"] for p in rows}) == 7,
         "expected seven distinct repositories and security families")
    for row, pin in zip(rows, PINS):
        case_id, repository, commit, source_blob, test_blob = pin
        must(isinstance(row, dict)
             and (row.get("packet_id"),row.get("repository"),row.get("fix_commit"),
                  row.get("source_post_fix_git_blob_sha1"),
                  row.get("regression_test_post_fix_git_blob_sha1")) == pin,
             "original pinned repo, commit, case or source/test blob mismatch")
        must(MIN_BLOB.fullmatch(commit) and MIN_BLOB.fullmatch(source_blob)
             and MIN_BLOB.fullmatch(test_blob), "malformed immutable source identity")
        must(row.get("fix_commit_url") ==
             f"https://github.com/{repository}/commit/{commit}",
             "unexpected exact commit URL")
        must(isinstance(row.get("source_file"),str)
             and isinstance(row.get("regression_test_file"),str)
             and row.get("source_url") ==
                 f"https://github.com/{repository}/blob/{commit}/{row['source_file']}"
             and row.get("test_url") ==
                 f"https://github.com/{repository}/blob/{commit}/{row['regression_test_file']}",
             "source or regression test URL no longer anchored to reviewed commit")
        must(all(isinstance(row.get(k),str) and MIN_SHA.fullmatch(row[k])
                 for k in ("source_patch_sha256","regression_test_patch_sha256")),
             "actual patch identity digest missing")
        must(isinstance(row.get("advisory_url"),str)
             and row["advisory_url"].startswith("https://github.com/")
             and isinstance(row.get("review_question"),str)
             and 35 <= len(row["review_question"]) <= 1500,
             "advisory or reviewer question missing")
        must(row.get("human_preference") is None
             and row.get("human_review_verified") is False
             and row.get("candidate_order_human_randomized") is False
             and row.get("source_patch_is_exploit_proof") is False
             and row.get("production_app_version_known") is False
             and row.get("production_traffic_exposure_known") is False
             and row.get("network_eligible") is False
             and row.get("training_authorized") is False
             and row.get("label_status") == "AUTHOR_DRAFT_WITH_REAL_SOURCE_NOT_ADJUDICATED",
             "cannot auto promote unreviewed or live-vulnerability claims")
        prerequisite = row.get("source_pinned_unreviewed_prerequisites")
        must(isinstance(prerequisite,list) and len(prerequisite) == 2
             and all(isinstance(x,dict)
                     and x.get("status") == "AUTHOR_HYPOTHESIS_NOT_HUMAN_VERIFIED"
                     and isinstance(x.get("question"),str) for x in prerequisite),
             "unverified prerequisites must remain explicitly provisional")
        choices = row.get("unreviewed_candidates")
        must(isinstance(choices,list) and len(choices) == 2
             and [c.get("id") for c in choices] == ["A","B"],
             "source must have exactly two distinct unreviewed answers")
        for candidate in choices:
            must(isinstance(candidate.get("text"),str)
                 and 40 <= len(candidate["text"]) <= 800
                 and candidate.get("sha256") == sha256(candidate["text"]),
                 "answer text hash or content changed without provenance")
        must(choices[0]["sha256"] != choices[1]["sha256"],
             "indistinguishable candidate texts")
    return rows


def make_pack(source: dict) -> dict:
    rows = validate_source(source)
    cases = []
    for case in rows:
        choices = case["unreviewed_candidates"]
        variants = []
        for orientation, order in (("original", (0,1)),("swapped",(1,0))):
            displayed = []
            for position, i in zip(("A","B"), order):
                candidate = choices[i]
                displayed.append({
                    "display_position":position,
                    "candidate_text_sha256":candidate["sha256"],
                    "text":candidate["text"],
                })
            variants.append({
                "presentation_id":case["packet_id"]+":"+orientation,
                "orientation":orientation,
                "reviewer_display_answers":displayed,
                "preference_label":None,
                "expert_review_verified":False,
                "score_by_model":None,
            })
        must(variants[0]["reviewer_display_answers"][0]["candidate_text_sha256"] ==
             variants[1]["reviewer_display_answers"][1]["candidate_text_sha256"]
             and variants[0]["reviewer_display_answers"][1]["candidate_text_sha256"] ==
             variants[1]["reviewer_display_answers"][0]["candidate_text_sha256"],
             "position swap changed answer content")
        cases.append({
            "case_id":case["packet_id"],
            "upstream_repository":case["repository"],
            "security_family":case["security_family"],
            "cve":case["cve"],
            "advisory_url":case["advisory_url"],
            "source_fix_commit":case["fix_commit"],
            "source_fix_commit_url":case["fix_commit_url"],
            "source_file_url":case["source_url"],
            "source_blob_sha1":case["source_post_fix_git_blob_sha1"],
            "source_patch_sha256":case["source_patch_sha256"],
            "regression_test_file_url":case["test_url"],
            "regression_test_blob_sha1":case["regression_test_post_fix_git_blob_sha1"],
            "regression_test_patch_sha256":case["regression_test_patch_sha256"],
            "question":case["review_question"],
            "researcher_prerequisites_need_review": [
                x["question"] for x in case["source_pinned_unreviewed_prerequisites"]],
            "two_counterbalanced_presentations":variants,
            "review_rubric":list(RUBRIC),
            "external_review_form_url":REVIEW_FORM,
            "independently_approved_answer":None,
            "independent_expert_reviewer_verified":False,
            "training_authorized":False,
            "network_eligible":False,
            "live_application_exploit_verified":False,
        })
    must(len(cases)==7 and
         all(len(x["two_counterbalanced_presentations"])==2 for x in cases),
         "incomplete counterbalanced packet count")
    return {
        "schema_version":1,
        "status":STATUS,
        "intent":"SECURITY_REVIEW_GENERAL",
        "security_families":7,
        "distinct_upstream_repositories":7,
        "upstream_commit_and_regression_test_pairs_verified":8,
        "source_backed_unique_review_cases":7,
        "counterbalanced_presentation_count":14,
        "independent_gold_labels":0,
        "new_eligible_anjoman_rows":0,
        "registered_evaluator":False,
        "general_model_accuracy_measured":False,
        "not_a_blind_holdout":True,
        "not_full_application_exploitation":True,
        "training_allowed":False,
        "source_data_sha256":sha256(json.dumps(source,sort_keys=True,separators=(",",":"))),
        "cases":cases,
        "reviewer_protocol":(
            "Read primary source, patch and regression test before judging. "
            "Do not treat candidate order as an answer label. The two variants "
            "show the SAME content in reversed positions; they are not separate "
            "vulnerability cases. Record evidence citations, uncertainties and "
            "ABSTAIN where justified. Reviewer identities and claims require "
            "separate independent verification before use as labels."
        ),
        "limitations":(
            "This is source-verifiable review material, not proof of deployed "
            "exploits, independent expert validation, a better LoRA, an accepted "
            "Telegraph evaluator or an accepted network contribution."
        )
    }


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description="Counterbalance 7 real public source-backed security cases for review")
    p.add_argument("--input",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        must(not args.out.exists() and not args.out.is_symlink(),
             "do not overwrite existing public proof")
        data=json.loads(args.input.read_text(encoding="utf-8"))
        pack=make_pack(data)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(pack,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({k:pack[k] for k in
            ("status","source_backed_unique_review_cases","counterbalanced_presentation_count",
             "independent_gold_labels","new_eligible_anjoman_rows","registered_evaluator")},indent=2))
        return 0
    except (ValueError,TypeError,KeyError,IndexError,OSError) as e:
        p.exit(1,"FALSUM COUNTERBALANCED SOURCE PACK REJECTED: "+str(e)+"\n")


if __name__=="__main__":
    raise SystemExit(main())
