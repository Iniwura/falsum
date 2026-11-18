"""Phase 4O: predeclared shortcut roster against unreviewed source-specific cases.

Not a model, not a Telegraph scoring adapter, not independent AppSec gold.
This tests whether cheap answer-only and lexical rules agree with *researcher*
hypotheses without actually reading the pinned upstream source.

Source provenance is inherited from the authentic Phase 3F seven-project pack.
The generated Phase 4G casebook is regenerated exactly and compared byte-neutral
at the structured-object level before any shortcut is measured.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from .phase4g_reasoning_puzzles import (
    SPECS, STATUS as CASEBOOK_STATUS, build as build_casebook,
)

STATUS = "PHASE4O_ADVERSARIAL_SHORTCUT_ROSTER_RESEARCHER_HYPOTHESES_NOT_GOLD"
ROSTER_STATUS = "PREDECLARED_NO_TRAINING_OR_PROMPT_TUNING"
SCHEMA_VERSION = 1
WORD = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]*")
STRONG = re.compile(
    r"\b(?:all|always|any|automatically|cannot|every|guarantees|"
    r"never|regardless|sufficient|unconditionally|universal)\b", re.I
)
HEDGES = re.compile(
    r"\b(?:can|could|depends|if|may|might|must|potentially|"
    r"requires|unless|verify|when|whether|while)\b", re.I
)
TECHNICAL = re.compile(
    r"(?:https?://|[A-Za-z]+\(|[a-z_]+\.[a-z_]+|"
    r"\b(?:header|proxy|sandbox|redirect|version|path|"
    r"authorization|request|attribute|url|security|response|"
    r"branch|root|file|option|config|regex|regexes)\b)", re.I
)
STOP = frozenset({
    "a","an","and","are","as","at","be","because","by","does","do",
    "for","from","has","have","how","in","is","it","its","of","on",
    "or","that","the","their","then","there","these","this","to",
    "was","what","when","which","while","with","would","you",
})
THRESHOLD_OUT_OF_14 = 11  # >=11/14 (79%) source-author agreement warrants a bias warning
MAX_CASEBOOK_BYTES = 250_000
MAX_SOURCE_BYTES = 600_000


class ShortcutAuditError(ValueError):
    """Fail closed on altered sources, casebooks, answer identities or status."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ShortcutAuditError(message)


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def words(text: str) -> list[str]:
    return [x.casefold() for x in WORD.findall(text)]


def feature_vector(question: str, answer: str) -> dict[str, int]:
    w = words(answer)
    q = set(words(question)) - STOP
    a = set(w) - STOP
    return {
        "characters": len(answer),
        "words": len(w),
        "strong_certainty_cues": len(STRONG.findall(answer)),
        "qualifying_cues": len(HEDGES.findall(answer)),
        "question_lexical_overlap": len(q & a),
        "technical_tokens": len(TECHNICAL.findall(answer)),
    }


# Fixed audit probes, not a learned classifier or a trainable evaluator.
# All are independent of upstream code and have no exposure to author labels.
ROSTER: tuple[tuple[str, str | None, str], ...] = (
    ("constant_A", None, "A"),
    ("constant_B", None, "B"),
    ("shorter_answer_chars", "characters", "min"),
    ("longer_answer_chars", "characters", "max"),
    ("shorter_answer_words", "words", "min"),
    ("longer_answer_words", "words", "max"),
    ("fewer_certainty_cues", "strong_certainty_cues", "min"),
    ("more_certainty_cues", "strong_certainty_cues", "max"),
    ("more_qualifiers", "qualifying_cues", "max"),
    ("fewer_qualifiers", "qualifying_cues", "min"),
    ("more_question_overlap", "question_lexical_overlap", "max"),
    ("less_question_overlap", "question_lexical_overlap", "min"),
    ("more_technical_tokens", "technical_tokens", "max"),
    ("fewer_technical_tokens", "technical_tokens", "min"),
)
EXPECTED_ROSTER_NAMES = (
    "constant_A","constant_B",
    "shorter_answer_chars","longer_answer_chars",
    "shorter_answer_words","longer_answer_words",
    "fewer_certainty_cues","more_certainty_cues",
    "more_qualifiers","fewer_qualifiers",
    "more_question_overlap","less_question_overlap",
    "more_technical_tokens","fewer_technical_tokens",
)


def choose(question: str, candidates: list[dict], rule: tuple[str, str | None, str]) -> str:
    name, field, order = rule
    require(len(candidates) == 2 and
            [c.get("position") for c in candidates] == ["A","B"],
            "candidate displays must be exactly A and B")
    if field is None:
        require(name in ("constant_A", "constant_B") and order in ("A","B"),
                "unknown position-only rule")
        return order
    require(field in feature_vector(question, candidates[0]["text"]), "unknown measured field")
    require(order in ("min","max"), "invalid feature ranking direction")
    first, second = [
        feature_vector(question,candidates[i]["text"])[field] for i in (0,1)
    ]
    if first == second:
        return "A"  # disclosed, deliberately weak position-tie default
    if order == "min":
        return "A" if first < second else "B"
    return "A" if first > second else "B"


def _validated_packs(source_raw: bytes, casebook_raw: bytes):
    require(isinstance(source_raw,bytes) and 0<len(source_raw)<=MAX_SOURCE_BYTES,
            "invalid or oversized verified-source report")
    require(isinstance(casebook_raw,bytes) and 0<len(casebook_raw)<=MAX_CASEBOOK_BYTES,
            "invalid or oversized 14-condition casebook")
    try:
        source = json.loads(source_raw)
        casebook = json.loads(casebook_raw)
    except (ValueError,UnicodeError) as e:
        raise ShortcutAuditError("source or casebook JSON invalid") from e
    require(isinstance(source,dict) and isinstance(casebook,dict),
            "source or casebook is not a JSON object")
    canonical, original_wording_diagnostic = build_casebook(source)
    require(casebook == canonical and casebook.get("status")==CASEBOOK_STATUS,
            "casebook differs from canonical pinned source and researcher-authored material")
    require(len(casebook["cases"])==14 and len(SPECS)==14 and
            set(rule[0] for rule in ROSTER)==set(EXPECTED_ROSTER_NAMES) and
            len(ROSTER)==len(EXPECTED_ROSTER_NAMES),
            "casebook/roster changed without preregistration")
    require(all(case["expert_label"] is None and
                case["independent_human_reviewer_verified"] is False and
                case["trainable"] is False and
                case["network_eligible"] is False and
                len(case["presentations"]) == 2
                for case in casebook["cases"]), "author evidence promoted to gold")
    return casebook, original_wording_diagnostic


def audit(source_raw: bytes, casebook_raw: bytes) -> dict:
    casebook, original_shortcut = _validated_packs(source_raw,casebook_raw)
    canonical_author = {case_id:correct for case_id,_,_,_,_,correct,*_ in SPECS}
    measurements = []
    for rule in ROSTER:
        total_hits = 0
        source_case_hypothesis_agreements = 0
        position_consistent = 0
        tie_count = 0
        for row in casebook["cases"]:
            case_id = row["case_id"]
            require(case_id in canonical_author, "unknown source case")
            wanted = canonical_author[case_id]
            original, swapped = row["presentations"]
            require([original["variant"],swapped["variant"]]==["original","swapped"],
                    "not an exact AB order and reverse")
            predictions = []
            for presentation in (original,swapped):
                candidates = presentation["candidate_answers"]
                require(len(candidates)==2 and
                        all(hashlib.sha256(c["text"].encode()).hexdigest()==c["sha256"]
                            for c in candidates), "broken source answer SHA identities")
                pick = choose(row["question"],candidates,rule)
                selected = candidates[0] if pick=="A" else candidates[1]
                predictions.append(selected["sha256"])
                correct_digest = original["candidate_answers"][0 if wanted=="A" else 1]["sha256"]
                total_hits += selected["sha256"] == correct_digest
            original_winner_hash = original["candidate_answers"][
                0 if wanted=="A" else 1]["sha256"]
            source_case_hypothesis_agreements += predictions[0]==original_winner_hash
            position_consistent += predictions[0]==predictions[1]
            field=rule[1]
            if field:
                first,second=original["candidate_answers"]
                tie_count += (feature_vector(row["question"],first["text"])[field] ==
                              feature_vector(row["question"],second["text"])[field])
        measurements.append({
            "baseline":rule[0],
            "author_hypothesis_agreements_across_14_original_displays":
                source_case_hypothesis_agreements,
            "author_hypothesis_agreements_across_28_swapped_displays":
                total_hits,
            "same_answer_chosen_after_AB_swap_out_of_14":position_consistent,
            "feature_ties_in_original_14":tie_count,
            "not_security_accuracy":True,
            "flag_high_shortcut_risk":
                source_case_hypothesis_agreements>=THRESHOLD_OUT_OF_14
                or total_hits>=2*THRESHOLD_OUT_OF_14,
        })
    data={x["baseline"]:x for x in measurements}
    require(data["constant_A"]["author_hypothesis_agreements_across_14_original_displays"]==7
            and data["constant_B"]["author_hypothesis_agreements_across_14_original_displays"]==7,
            "original researcher authorship balance changed")
    require(data["constant_A"]["author_hypothesis_agreements_across_28_swapped_displays"]==14
            and data["constant_B"]["author_hypothesis_agreements_across_28_swapped_displays"]==14,
            "position swaps no longer represent true counterbalance")
    require(original_shortcut["independent_ground_truth"] is False
            and original_shortcut["author_A_positions"]==7
            and original_shortcut["author_B_positions"]==7,
            "Phase 4G semantic guard was misrepresented")
    flagged=[item["baseline"] for item in measurements if item["flag_high_shortcut_risk"]]
    return {
        "schema_version":SCHEMA_VERSION,
        "status":STATUS,
        "audit_design":ROSTER_STATUS,
        "source_report_sha256":sha256(source_raw),
        "casebook_sha256":sha256(casebook_raw),
        "source_cases":7,
        "author_written_reasoning_conditions":14,
        "exact_AB_presentations":28,
        "shortcuts":len(ROSTER),
        "predeclared_high_risk_threshold_original_correct_or_more":THRESHOLD_OUT_OF_14,
        "predeclared_high_risk_threshold_swapped_correct_or_more":2*THRESHOLD_OUT_OF_14,
        "flags_high_shortcut_risk":bool(flagged),
        "flagged_baselines":flagged,
        "baselines":measurements,
        "original_phase4g_simple_cue_rule_agreement_out_of_14":
            original_shortcut["language_shortcut_author_agreements"],
        "position_swap_is_not_independent_new_case":True,
        "no_new_project_holdout":True,
        "old_public_sources_previously_studied":True,
        "researcher_hypotheses_not_gold":True,
        "independent_appsec_gold_labels":0,
        "new_anjoman_rows":0,
        "foundation_model_called":False,
        "trained_evaluator":False,
        "model_improvement_or_network_ranking_proven":False,
        "registered_evaluator":False,
        "expert_source_review_still_needed":True,
        "interpretation": (
            "This source-bound author-hypothesis diagnostic measures whether "
            "answer-only and question-wording shortcuts can explain preferred "
            "response choices. It is not statistical inference of independent "
            "security accuracy, model scoring, new gold labels, new accepted "
            "network rows or proof a hidden shortcut does not exist."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Review author hypotheses for cheap lexical shortcuts")
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--casebook",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        require(args.out.resolve() not in
                {args.source.resolve(),args.casebook.resolve()},
                "output must not alias source inputs")
        require(not args.out.exists() and not args.out.is_symlink(), "refuse overwrite")
        data=audit(args.source.read_bytes(),args.casebook.read_bytes())
        args.out.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            json.dump(data,stream,indent=2,sort_keys=True)
            stream.write("\n")
        print(json.dumps({
            "status":data["status"],
            "source_cases":data["source_cases"],
            "author_written_reasoning_conditions":data["author_written_reasoning_conditions"],
            "shortcuts":data["shortcuts"],
            "flagged_baselines":data["flagged_baselines"],
            "independent_appsec_gold_labels":0,
            "trained_evaluator":False,
            "report_written":str(args.out),
        },indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError) as e:
        p.exit(1,"FALSUM PHASE 4O SHORTCUT AUDIT FAILED: "+str(e)[:170]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
