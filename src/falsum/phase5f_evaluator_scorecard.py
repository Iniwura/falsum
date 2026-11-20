"""Reproducible scorecard for EXTERNAL typed source-claim predictions.

An open-book, bounded evaluation MATERIAL harness using five actual historical
upstream source-test witnesses. It is not independent AppSec gold, an unseen
model benchmark, a new trained scorer, or a Telegraph registered evaluator.

The 80 items exercise source-test PASS/FAIL, out-of-scope production claims,
and forged execution digests. Unlike the published Phase 5D workbench, a
caller supplies their OWN predictions. These are checked against the frozen
source-derived reference after validating the underlying original evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from . import phase4v_real_source_witness_site as source
from .source_review_witness_gate import CLAIMS, RESULTS

STATUS = "PHASE5F_OPEN_REPRODUCIBLE_TYPED_PREDICTION_EVALUATION_NOT_BLIND_MODEL_GOLD"
CHALLENGE_STATUS = "PHASE5F_PUBLIC_OPEN_BOOK_SOURCE_FACT_CHALLENGE_NO_LABELS"
PREDICTION_STATUS = "PHASE5F_CALLER_SUPPLIED_PREDICTIONS_NOT_VERIFIED_EXPERT"
BASELINES = ("always-abstain", "always-supported", "always-contradicted")
COUNTS = {"SUPPORTED": 10, "CONTRADICTED": 10, "ABSTAIN": 60}
MAX_INPUT = 80_000


class ScorecardError(ValueError):
    """Missing source provenance, forged predictions, or invalid scorecard."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ScorecardError(reason)


def canonical(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _pairs(entries: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in entries:
        require(key not in result, "untrusted prediction JSON duplicates a key")
        result[key] = value
    return result


def read_predictions(path: Path) -> dict:
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= MAX_INPUT,
            "missing/symlinked/oversized prediction input")
    try:
        record = json.loads(path.read_bytes(), object_pairs_hook=_pairs)
    except (ValueError, UnicodeError) as exc:
        raise ScorecardError("invalid prediction JSON") from exc
    require(isinstance(record, dict), "predictions must be a JSON object")
    return record


def construct(root: Path = source.ROOT) -> tuple[dict, dict, dict]:
    """Always regenerate facts from the exact authenticated original source ZIP."""
    witness = source.assemble(root)
    require(witness["status"] == source.STATUS
            and witness["source_fix_stage_count"] == 5
            and witness["upstream_project_count"] == 4
            and witness["by_construction_verdict_counts"] == COUNTS
            and witness["independent_appsec_expert_gold_labels"] == 0
            and witness["trained_model_improvement_proven"] is False
            and witness["network_evaluator_registered"] is False,
            "unapproved source evidence or falsely promoted independent gold")
    items, answers = [], {}
    for case in witness["cases"]:
        require(len(case["decisions"]) == 16
                and case["actions_run_url"].startswith("https://github.com/")
                and case["source_parent_url"].startswith("https://github.com/")
                and case["source_fixed_url"].startswith("https://github.com/"),
                "source stage is missing real public revision/test evidence")
        for revision in ("parent", "fixed"):
            commit = case["parent_commit"] if revision == "parent" else case["fixed_commit"]
            src = case["source_parent_url"] if revision == "parent" else case["source_fixed_url"]
            for claim_type in CLAIMS:
                for receipt in ("original", "tampered"):
                    id_value = f"{case['id']}|{revision}|{claim_type}|{receipt}"
                    decision = case["decisions"][f"{revision}|{claim_type}|{receipt}"]
                    require(decision["verdict"] in RESULTS and id_value not in answers,
                            "malformed original source-derived result")
                    answers[id_value] = decision["verdict"]
                    items.append({
                        "id": id_value,
                        "historical_upstream_case": case["id"],
                        "source_repository": case["repository"],
                        "revision": revision,
                        "git_commit": commit,
                        "source_url": src,
                        "upstream_regression_test_url": case["upstream_test_url"],
                        "original_real_execution_run_url": case["actions_run_url"],
                        "claim_type": claim_type,
                        "review_statement": source.CLAIM_COPY[claim_type],
                        "execution_receipt_sha256": (
                            case["original_execution_receipt_sha256"]
                            if receipt == "original" else "0" * 64
                        ),
                        "receipt_integrity": receipt,
                        "decision_options": list(RESULTS),
                    })
    require(len(items) == len(answers) == 80,
            "fewer or repeated structured security-review challenge questions")
    require({value: list(answers.values()).count(value) for value in RESULTS} == COUNTS,
            "source-derived reference distribution changed")
    challenge = {
        "schema_version": 1,
        "status": CHALLENGE_STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "evaluation_scope": "OPEN_BOOK_TYPED_HISTORICAL_SOURCE_TEST_JUDGMENT",
        "reference_source_report_sha256": digest(canonical(witness)),
        "source_fix_stages": 5,
        "upstream_projects": 4,
        "questions": items,
        "answer_labels_in_challenge": False,
        "source_pins_and_original_test_receipts_public": True,
        "independent_expert_gold_labels": 0,
        "trained_model_improvement_proven": False,
        "blind_holdout": False,
        "registered_telegraph_evaluator": False,
        "limitations": (
            "Questions and code/test evidence are public and source-derived. "
            "This is NOT an independently adjudicated or blind test. Use it "
            "to measure how a candidate handles historical typed source "
            "facts, invalid evidence and unsupported security claims. "
            "Do not report scores as general natural-language AppSec accuracy."
        ),
    }
    return challenge, answers, witness


def prediction_template(challenge: dict) -> dict:
    """Null placeholders force an evaluator to supply fresh predictions."""
    return {
        "schema_version": 1,
        "status": PREDICTION_STATUS,
        "challenge_sha256": digest(canonical(challenge)),
        "predictions": [
            {"id": item["id"], "verdict": None}
            for item in challenge["questions"]
        ],
    }


def validate_predictions(challenge: dict, supplied: dict) -> dict[str, str]:
    require(set(supplied) == {"schema_version", "status", "challenge_sha256", "predictions"}
            and type(supplied["schema_version"]) is int
            and supplied["schema_version"] == 1
            and supplied["status"] == PREDICTION_STATUS
            and supplied["challenge_sha256"] == digest(canonical(challenge)),
            "external predictions missing matching frozen challenge SHA or allowed schema")
    predictions = supplied["predictions"]
    require(isinstance(predictions, list)
            and len(predictions) == len(challenge["questions"]),
            "all 80 predictions are required, no partial/extra rows")
    ids = [item["id"] for item in challenge["questions"]]
    result = {}
    for position, (row, ident) in enumerate(zip(predictions, ids)):
        require(isinstance(row, dict) and set(row) == {"id", "verdict"}
                and row["id"] == ident and row["verdict"] in RESULTS,
                "missing, reordered, unsupported or extra prediction at position "
                + str(position))
        result[ident] = row["verdict"]
    require(len(result) == 80, "duplicated prediction case IDs")
    return result


def baseline_predictions(challenge: dict, strategy: str) -> dict[str, str]:
    require(strategy in BASELINES, "unsupported baseline strategy")
    label = {
        "always-abstain": "ABSTAIN",
        "always-supported": "SUPPORTED",
        "always-contradicted": "CONTRADICTED",
    }[strategy]
    return {item["id"]: label for item in challenge["questions"]}


def score(challenge: dict, answers: dict[str, str], predictions: dict[str, str],
          *, origin: str) -> dict:
    require(origin in ("EXTERNAL_UNVERIFIED_PREDICTIONS", "SYNTHETIC_CONSTANT_BASELINE"),
            "cannot promote predictions into human-certified answers")
    ids = [item["id"] for item in challenge["questions"]]
    require(len(ids) == len(answers) == len(predictions) == 80
            and set(ids) == set(answers) == set(predictions)
            and all(answers[i] in RESULTS and predictions[i] in RESULTS for i in ids),
            "score inputs missing the authenticated public-source questions")
    matrix = {
        true: {pred: 0 for pred in RESULTS}
        for true in RESULTS
    }
    for ident in ids:
        matrix[answers[ident]][predictions[ident]] += 1
    actual_distribution = {label: sum(matrix[label].values()) for label in RESULTS}
    require(actual_distribution == COUNTS,
            "authenticated source-fact classes changed")
    correct = sum(matrix[k][k] for k in RESULTS)
    recalls = {
        label: round(matrix[label][label] / actual_distribution[label], 6)
        for label in RESULTS
    }
    macro = round(sum(recalls.values()) / 3, 6)
    # A genuine source-sensitive reversal requires all four original-receipt
    # PASS/FAIL statements for one historical fix stage to be scored correctly.
    reversals = 0
    cases = list(source.CASE_COPY)
    for case_id in cases:
        relevant = [
            f"{case_id}|{revision}|{kind}|original"
            for revision in ("parent", "fixed")
            for kind in CLAIMS[:2]
        ]
        if all(answers[i] == predictions[i] for i in relevant):
            reversals += 1
    overclaim = sum(
        predictions[i] != "ABSTAIN" and answers[i] == "ABSTAIN" for i in ids
    )
    evidence_undercall = sum(
        predictions[i] == "ABSTAIN" and answers[i] != "ABSTAIN" for i in ids
    )
    return {
        "schema_version": 1,
        "status": STATUS,
        "prediction_provenance": origin,
        "challenge_sha256": digest(canonical(challenge)),
        "source_evidence_sha256": challenge["reference_source_report_sha256"],
        "intent": "SECURITY_REVIEW_GENERAL",
        "historical_upstream_source_cases": 5,
        "distinct_upstream_projects": 4,
        "source_test_claims_scored": 80,
        "reference_class_distribution": COUNTS,
        "confusion_matrix_true_rows_predicted_columns": matrix,
        "exact_matches": correct,
        "raw_exact_match_ratio": round(correct / 80, 6),
        "per_reference_class_recall": recalls,
        "macro_class_recall": macro,
        "fully_correct_parent_fix_reversals": reversals,
        "source_fix_stages_for_reversal": 5,
        "unsupported_confident_claims": overclaim,
        "supported_or_contradicted_facts_abstained_on": evidence_undercall,
        "always_abstain_raw_accuracy_is_75_percent": True,
        "source_reference_is_public_and_author_constructed": True,
        "independently_certified_human_appsec_gold_labels": 0,
        "trained_model_performance_improvement_claimed": False,
        "network_evaluator_registered": False,
        "official_h2_entry_submitted": False,
        "scope_warning": (
            "This is an OPEN-BOOK, AUTHOR-CONSTRUCTED, HISTORICAL STRUCTURED "
            "security-claim benchmark grounded in real upstream Git source/test "
            "executions. A high score does not prove general prose review "
            "quality, novel model accuracy, independent gold, H2 acceptance "
            "or an improved registered Telegraph scorer."
        ),
    }


def _write(path: Path, record: dict, forbidden: tuple[Path, ...] = ()) -> None:
    require(not path.exists() and not path.is_symlink()
            and path.resolve() not in {item.resolve() for item in forbidden},
            "output must be new, not a source or prediction file")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2, sort_keys=True, ensure_ascii=False)
        stream.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Open-book typed source-test evaluator prediction scorecard, NOT expert gold"
    )
    parser.add_argument("--root", type=Path, default=source.ROOT,
                        help="public FALSUM repository root with original Git evidence")
    sub = parser.add_subparsers(dest="mode", required=True)
    export = sub.add_parser("export", help="write the 80 no-answer public questions and blank prediction template")
    export.add_argument("--challenge-out", type=Path, required=True)
    export.add_argument("--template-out", type=Path, required=True)
    user = sub.add_parser("score", help="score a complete user-supplied prediction file against frozen source facts")
    user.add_argument("--predictions", type=Path, required=True)
    user.add_argument("--out", type=Path, required=True)
    baseline = sub.add_parser("baseline", help="score a declared trivial constant-prediction control")
    baseline.add_argument("--strategy", choices=BASELINES, required=True)
    baseline.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        challenge, answers, witness = construct(args.root)
        if args.mode == "export":
            require(args.challenge_out.resolve() != args.template_out.resolve(),
                    "challenge and template cannot overwrite one another")
            require(not args.challenge_out.exists()
                    and not args.template_out.exists(),
                    "new challenge and blank template outputs required")
            _write(args.challenge_out, challenge)
            _write(args.template_out, prediction_template(challenge),
                   (args.challenge_out,))
            print(json.dumps({"challenge": str(args.challenge_out),
                              "template": str(args.template_out),
                              "challenge_sha256": digest(canonical(challenge)),
                              "answer_key_exported": False, "questions": 80}, sort_keys=True))
        else:
            if args.mode == "score":
                candidate = read_predictions(args.predictions)
                predictions = validate_predictions(challenge, candidate)
                kind = "EXTERNAL_UNVERIFIED_PREDICTIONS"
                sources = (args.predictions,)
            else:
                predictions = baseline_predictions(challenge, args.strategy)
                kind = "SYNTHETIC_CONSTANT_BASELINE"
                sources = ()
            result = score(challenge, answers, predictions, origin=kind)
            if args.mode == "baseline":
                result["baseline_strategy"] = args.strategy
            _write(args.out, result, sources)
            print(json.dumps({
                "source_test_claims": 80, "provenance": kind,
                "raw_match_ratio": result["raw_exact_match_ratio"],
                "macro_class_recall": result["macro_class_recall"],
                "fully_correct_source_reversals": result["fully_correct_parent_fix_reversals"],
                "independent_gold": 0,
            }, sort_keys=True))
        return 0
    except (ScorecardError, OSError, KeyError, TypeError, ValueError, UnicodeError) as exc:
        parser.exit(1, "FALSUM OPEN SOURCE EVALUATOR SCORECARD BLOCKED: "
                    + str(exc)[:200] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
