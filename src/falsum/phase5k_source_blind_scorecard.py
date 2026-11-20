"""Phase 5K: falsify a source-blind scorecard shortcut, then reduce obvious cues.

All reference classes are from *public author-constructed historical source
facts*, authenticated from actual upstream source/test CI. This is not an
independent expert gold benchmark, sealed model holdout, network scorer, or
measured model improvement. Publishing deterministic case-slot allocation and
the source history means even v2 is publicly reverse-engineerable: it removes
a trivial answer-bearing revision column, not all possible answer leakage.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from . import phase5f_evaluator_scorecard as legacy
from . import phase4v_real_source_witness_site as source
from .source_review_witness_gate import RESULTS

STATUS = "PHASE5K_OPEN_BOOK_BALANCED_SOURCE_ROLE_NEUTRAL_NOT_BLIND_MODEL_ACCURACY"
QUESTION_STATUS = "PHASE5K_30_BALANCED_PUBLIC_HISTORICAL_SOURCE_QUESTIONS"
PREDICTION_STATUS = "PHASE5K_UNVERIFIED_EXTERNAL_TYPED_SOURCE_RESPONSES"
AUDIT_STATUS = "PHASE5K_SOURCE_BLIND_LEGACY_ANSWER_LEAK_CONFIRMED"
COUNT_BY_CLASS = {"SUPPORTED": 10, "CONTRADICTED": 10, "ABSTAIN": 10}
MAX_QUESTIONS = 30
MAX_REASON = 700


class SourceShortcutError(ValueError):
    """Cannot authenticate original source facts or accept malformed predictions."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SourceShortcutError(reason)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: dict) -> bytes:
    return legacy.canonical(value)


def _legacy_metadata_only_verdict(question: dict) -> str:
    """This attacker does NOT open the Git/source/test URL or read a model."""
    revision = question["revision"]
    claim = question["claim_type"]
    integrity = question["receipt_integrity"]
    require(revision in ("parent", "fixed")
            and claim in source.CLAIMS
            and integrity in ("original", "tampered"),
            "legacy challenge metadata no longer recognized")
    if integrity == "tampered" or claim in (
        "CONFIRMED_PRODUCTION_EXPLOIT",
        "GUARANTEED_UNIVERSAL_APPLICATION_SAFETY",
    ):
        return "ABSTAIN"
    if claim == "UPSTREAM_REGRESSION_PASSES":
        return "SUPPORTED" if revision == "fixed" else "CONTRADICTED"
    return "SUPPORTED" if revision == "parent" else "CONTRADICTED"


def legacy_leak_audit() -> dict:
    challenge, answers, original_proof = legacy.construct()
    pred = {q["id"]: _legacy_metadata_only_verdict(q)
            for q in challenge["questions"]}
    require(len(pred) == 80 and len(answers) == 80
            and set(pred) == set(answers), "legacy challenge not exactly 80 cases")
    correct = sum(pred[k] == answers[k] for k in pred)
    require(correct == 80, "metadata shortcut unexpectedly fails to reproduce all legacy labels")
    require(original_proof["precomputed_python_evaluations"] == 80
            and original_proof["independent_appsec_expert_gold_labels"] == 0,
            "legacy proof no longer authentic or has inappropriate gold promotion")
    return {
        "schema_version": 1,
        "status": AUDIT_STATUS,
        "legacy_challenge_sha256": digest(canonical(challenge)),
        "legacy_questions": 80,
        "source_blind_predictions_matching": correct,
        "source_blind_raw_match": 1.0,
        "source_blind_macro_class_recall": 1.0,
        "source_blind_full_parent_fix_reversals": 5,
        "source_code_or_regression_test_read": False,
        "model_inference_used": False,
        "answer_bearing_public_metadata": [
            "revision", "claim_type", "receipt_integrity",
        ],
        "unrestricted_perfect_legacy_score_not_evidence_of_semantic_source_review": True,
        "old_model_improvement_proven": False,
        "new_anjoman_rows": 0,
        "independent_human_gold": 0,
        "legacy_scorecard_as_model_accuracy": "INVALID",
        "conclusion": (
            "A deterministic source-blind baseline reconstructs all 80 source labels "
            "using only three publicly exposed question fields. Even a 100% original "
            "score is not proof of source understanding, generalization or model gain."
        ),
    }


def build(root: Path = source.ROOT) -> tuple[dict, dict[str, str], dict[str, dict]]:
    """Build a class-balanced v2 challenge using role-neutral source commits.

    5 original historic stages x [4 code-test facts + 1 unsupported deployed
    assertion + 1 forged receipt] = 30: 10/10/10 verified classes.

    Slots alternate by publicly documented per-case index. This destroys the
    *unconditional* parent/fixed metadata mapping but is intentionally not a
    secret blind benchmark: the algorithm, Git commits and source evidence
    are public, and attackers can examine the repo to discover answers.
    """
    challenge, answers, proof = legacy.construct(root)
    require(proof["precomputed_python_evaluations"] == 80
            and proof["source_fix_stage_count"] == 5
            and proof["upstream_project_count"] == 4,
            "legacy source witness case count changed")
    cases = list(source.CASE_COPY)
    require(len(cases) == 5, "five originally authenticated historical stages required")
    source_cases = {c["id"]: c for c in proof["cases"]}
    require(set(source_cases) == set(cases), "original source evidence stages changed")
    v1_rows = {row["id"]: row for row in challenge["questions"]}
    new_questions: list[dict] = []
    new_answers: dict[str, str] = {}
    mapping: dict[str, dict] = {}
    for index, case_id in enumerate(cases):
        case = source_cases[case_id]
        # V2 deliberately does not reveal which visible commit is the parent.
        # For three case groups, A is parent; for two, B is parent. Public,
        # deterministic assignment is NOT hidden source-independent gold.
        a_is_parent = index % 2 == 0
        for revision in ("parent", "fixed"):
            slot = ("A" if a_is_parent else "B") if revision == "parent" else (
                "B" if a_is_parent else "A"
            )
            selections = [
                ("UPSTREAM_REGRESSION_PASSES", "original"),
                ("UPSTREAM_REGRESSION_FAILS", "original"),
            ]
            if revision == "parent":
                selections.append(("CONFIRMED_PRODUCTION_EXPLOIT", "original"))
            else:
                selections.append(("UPSTREAM_REGRESSION_PASSES", "tampered"))
            for claim, integrity in selections:
                legacy_id = f"{case_id}|{revision}|{claim}|{integrity}"
                old = v1_rows[legacy_id]
                ident = digest(
                    ("phase5k/open-public-v2/" + legacy_id).encode("utf-8")
                )[:32]
                require(ident not in new_answers, "duplicate opaque source question id")
                new_answers[ident] = answers[legacy_id]
                mapping[ident] = {
                    "case": case_id, "revision": revision,
                    "claim": claim, "receipt_integrity": integrity,
                    "v1_id": legacy_id,
                }
                require(old["git_commit"] == (
                    case["parent_commit"] if revision == "parent" else case["fixed_commit"]
                ), "legacy source Git revision identity mismatch")
                new_questions.append({
                    "id": ident,
                    "historical_source_case": case_id,
                    "source_project": case["repository"],
                    "source_slot": slot,
                    # Only immutable Git and actual source links; NO "parent"/"fixed"
                    # role, no "original/tampered" integrity classification.
                    "source_git_commit": old["git_commit"],
                    "source_code_url": old["source_url"],
                    "upstream_security_regression_test_url":
                        old["upstream_regression_test_url"],
                    "actual_original_test_ci_url":
                        old["original_real_execution_run_url"],
                    "test_statement": old["review_statement"],
                    "submitted_execution_receipt_sha256":
                        old["execution_receipt_sha256"],
                    "canonical_original_execution_receipt_sha256":
                        case["original_execution_receipt_sha256"],
                    "allowed_verdicts": ["SUPPORTED", "CONTRADICTED", "ABSTAIN"],
                })
    # Interleave different projects, source slots and classes so trivial
    # display position is not a label. Deterministic source-only ordering.
    new_questions.sort(key=lambda q: digest(
        ("phase5k/fixed-public-mix/" + q["id"]).encode("ascii")
    ))
    require(len(new_questions) == len(new_answers) == len(mapping) == MAX_QUESTIONS,
            "v2 missing or duplicated historical source questions")
    require(Counter(new_answers.values()) == COUNT_BY_CLASS,
            "balanced 10/10/10 source-backed v2 task labels changed")
    forbid = {"revision", "receipt_integrity", "parent_or_fixed",
              "expected", "label", "answer", "v1_id"}
    require(all(not (forbid & set(row)) for row in new_questions),
            "v2 public question leaked explicit source-role or verdict metadata")
    doc = {
        "schema_version": 2,
        "status": QUESTION_STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "historical_test_stages": 5,
        "distinct_projects": 4,
        "questions": new_questions,
        "question_count": MAX_QUESTIONS,
        "reference_source_evidence_sha256": legacy.digest(canonical(proof)),
        "answer_labels_exported": False,
        "class_balancing_disclosed": True,
        "not_source_or_model_blind": True,
        "independent_human_appsec_gold": 0,
        "network_evaluator_registered": False,
        "model_improvement_proven": False,
        "scope_warning": (
            "The public challenge removes explicit answer-bearing revision and "
            "integrity class metadata, and balances 10 supported/10 contradicted/"
            "10 abstained source-derived labels. Commit and source/test identities, "
            "role assignment code and historical outcomes remain public. Therefore "
            "this is NOT a sealed holdout, expert gold, an independent benchmark "
            "or measured neural model accuracy. Public code can still be used "
            "to reverse engineer the labels; measure actual outside predictions "
            "separately and preserve their origin."
        ),
    }
    return doc, new_answers, mapping


def template(challenge: dict) -> dict:
    return {
        "schema_version": 2,
        "status": PREDICTION_STATUS,
        "challenge_sha256": digest(canonical(challenge)),
        "predictions": [
            {"id": item["id"], "verdict": None}
            for item in challenge["questions"]
        ],
    }


def validate(challenge: dict, candidate: dict) -> dict[str, str]:
    require(isinstance(candidate, dict)
            and set(candidate) == {"schema_version", "status",
                                    "challenge_sha256", "predictions"}
            and type(candidate["schema_version"]) is int
            and candidate["schema_version"] == 2
            and candidate["status"] == PREDICTION_STATUS
            and candidate["challenge_sha256"] == digest(canonical(challenge)),
            "unverified predictions do not match the exact v2 challenge")
    entries = candidate["predictions"]
    expected_ids = [item["id"] for item in challenge["questions"]]
    require(isinstance(entries, list) and len(entries) == MAX_QUESTIONS,
            "all 30 decisions must be supplied in canonical order")
    out = {}
    for i, (row, ident) in enumerate(zip(entries, expected_ids)):
        require(isinstance(row, dict) and set(row) == {"id", "verdict"}
                and row["id"] == ident and row["verdict"] in RESULTS,
                "invalid, reordered, unknown or unfilled prediction at index " + str(i))
        out[ident] = row["verdict"]
    require(len(out) == MAX_QUESTIONS, "duplicate question IDs")
    return out


def baseline(challenge: dict, mode: str) -> dict[str, str]:
    rules = {
        "always-abstain": "ABSTAIN",
        "always-supported": "SUPPORTED",
        "always-contradicted": "CONTRADICTED",
    }
    if mode in rules:
        return {q["id"]: rules[mode] for q in challenge["questions"]}
    require(mode == "slot-a-is-parent",
            "unknown synthetic source-blind baseline")
    out = {}
    for q in challenge["questions"]:
        text = q["test_statement"]
        if (q["submitted_execution_receipt_sha256"]
                != q["canonical_original_execution_receipt_sha256"]
                or text == source.CLAIM_COPY["CONFIRMED_PRODUCTION_EXPLOIT"]
                or text == source.CLAIM_COPY["GUARANTEED_UNIVERSAL_APPLICATION_SAFETY"]):
            out[q["id"]] = "ABSTAIN"
        elif text == source.CLAIM_COPY["UPSTREAM_REGRESSION_PASSES"]:
            out[q["id"]] = (
                "CONTRADICTED" if q["source_slot"] == "A" else "SUPPORTED"
            )
        elif text == source.CLAIM_COPY["UPSTREAM_REGRESSION_FAILS"]:
            out[q["id"]] = (
                "SUPPORTED" if q["source_slot"] == "A" else "CONTRADICTED"
            )
        else:
            raise SourceShortcutError("unexpected public source claim text")
    return out


def evaluate(challenge: dict, expected: dict[str, str], mapping: dict[str, dict],
             predicted: dict[str, str], *, origin: str) -> dict:
    require(origin in ("EXTERNAL_UNVERIFIED_PREDICTIONS",
                       "SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE"),
            "prediction origin cannot be promoted into expert gold")
    require(len(expected) == len(mapping) == len(predicted) == MAX_QUESTIONS
            and set(expected) == set(predicted) == set(mapping)
            and all(expected[x] in RESULTS and predicted[x] in RESULTS
                    for x in expected), "mismatched protected source reference keys")
    matrix = {truth: {guess: 0 for guess in RESULTS} for truth in RESULTS}
    for ident, truth in expected.items():
        matrix[truth][predicted[ident]] += 1
    distribution = {k: sum(matrix[k].values()) for k in RESULTS}
    require(distribution == COUNT_BY_CLASS, "underlying v2 source class balance changed")
    exact = sum(matrix[k][k] for k in RESULTS)
    recalls = {
        k: round(matrix[k][k] / distribution[k], 6)
        for k in RESULTS
    }
    reversal = 0
    for case_id in source.CASE_COPY:
        facts = [
            ident for ident, row in mapping.items()
            if row["case"] == case_id
            and row["receipt_integrity"] == "original"
            and row["claim"] in source.CLAIMS[:2]
        ]
        require(len(facts) == 4, "v2 missing complete original-receipt source reversal")
        reversal += all(predicted[x] == expected[x] for x in facts)
    wrong_confidence = sum(
        expected[x] == "ABSTAIN" and predicted[x] != "ABSTAIN" for x in expected
    )
    unnecessary_abstention = sum(
        expected[x] != "ABSTAIN" and predicted[x] == "ABSTAIN" for x in expected
    )
    return {
        "schema_version": 2,
        "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "source_reference_is_public_not_expert_gold": True,
        "not_an_independent_blind_security_review_accuracy_measurement": True,
        "question_set": "PUBLIC_BALANCED_SOURCE_ROLE_NEUTRAL_V2",
        "candidate_origin": origin,
        "challenge_sha256": digest(canonical(challenge)),
        "source_evidence_sha256": challenge["reference_source_evidence_sha256"],
        "historical_test_stages": 5,
        "distinct_upstream_projects": 4,
        "typed_source_claims_scored": MAX_QUESTIONS,
        "reference_class_distribution": COUNT_BY_CLASS,
        "confusion_matrix_true_rows_predicted_columns": matrix,
        "exact_matches": exact,
        "raw_match_ratio": round(exact / MAX_QUESTIONS, 6),
        "macro_class_recall": round(sum(recalls.values()) / len(RESULTS), 6),
        "per_class_recall": recalls,
        "complete_source_sensitive_parent_fix_reversals": reversal,
        "max_possible_source_reversals": 5,
        "unsupported_confident_verdicts": wrong_confidence,
        "known_source_facts_missed_by_abstaining": unnecessary_abstention,
        "independent_human_gold_labels": 0,
        "actual_trained_model_comparison": False,
        "registered_telegraph_evaluator": False,
        "official_H2_entry_submitted": False,
        "scope_warning": challenge["scope_warning"],
    }


def report() -> dict:
    l = legacy_leak_audit()
    challenge, answers, mapping = build()
    default = evaluate(
        challenge, answers, mapping, baseline(challenge, "slot-a-is-parent"),
        origin="SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE",
    )
    abstain = evaluate(
        challenge, answers, mapping, baseline(challenge, "always-abstain"),
        origin="SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE",
    )
    require(default["exact_matches"] == 22
            and default["complete_source_sensitive_parent_fix_reversals"] == 3
            and abstain["exact_matches"] == 10
            and abstain["complete_source_sensitive_parent_fix_reversals"] == 0,
            "declared shortcut stress results changed")
    return {
        "schema_version": 1,
        "status": AUDIT_STATUS,
        "legacy": l,
        "balanced_v2": {
            "challenge_sha256": digest(canonical(challenge)),
            "questions": 30,
            "classes": COUNT_BY_CLASS,
            "source_blind_slot_baseline": default,
            "always_abstain_baseline": abstain,
        },
        "public_open_book_not_independent_model_validation": True,
        "first_place_claim_proven": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Falsify Phase5F metadata shortcut and publish balanced v2 source questions"
    )
    sub = parser.add_subparsers(dest="mode", required=True)
    a = sub.add_parser("audit", help="show trivial 80/80 source-blind leakage")
    a.add_argument("--out", type=Path, required=True)
    e = sub.add_parser("export", help="write public role-neutral questions and null template")
    e.add_argument("--questions-out", type=Path, required=True)
    e.add_argument("--template-out", type=Path, required=True)
    b = sub.add_parser("baseline", help="evaluate explicit source-blind controls on v2")
    b.add_argument("--strategy", required=True, choices=(
        "always-abstain", "always-supported", "always-contradicted",
        "slot-a-is-parent",
    ))
    b.add_argument("--out", type=Path, required=True)
    s = sub.add_parser("score", help="score complete external predictions on public v2 facts")
    s.add_argument("--predictions", type=Path, required=True)
    s.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "audit":
            legacy._write(args.out, report())
            print(json.dumps({"legacy_metadata_only_agreement": "80/80",
                              "v2_questions": 30,
                              "v2_slot_only_agreement": "22/30",
                              "model_improvement": False}, sort_keys=True))
            return 0
        challenge, answers, mapping = build()
        if args.mode == "export":
            require(args.questions_out.resolve() != args.template_out.resolve(),
                    "challenge and template paths must be distinct")
            require(not args.questions_out.exists()
                    and not args.template_out.exists(),
                    "challenge and template outputs must both be new")
            legacy._write(args.questions_out, challenge)
            legacy._write(args.template_out, template(challenge), (args.questions_out,))
            print(json.dumps({"questions": 30,
                              "answer_labels_exported": False,
                              "class_balance_authored": COUNT_BY_CLASS}, sort_keys=True))
            return 0
        if args.mode == "baseline":
            predictions = baseline(challenge, args.strategy)
            origin = "SYNTHETIC_DISCLOSED_SOURCE_BLIND_BASELINE"
            forbidden = ()
        else:
            supplied = legacy.read_predictions(args.predictions)
            predictions = validate(challenge, supplied)
            origin = "EXTERNAL_UNVERIFIED_PREDICTIONS"
            forbidden = (args.predictions,)
        scored = evaluate(challenge, answers, mapping, predictions, origin=origin)
        if args.mode == "baseline":
            scored["baseline"] = args.strategy
        legacy._write(args.out, scored, forbidden)
        print(json.dumps({"questions": scored["typed_source_claims_scored"],
                          "exact": scored["exact_matches"],
                          "macro_recall": scored["macro_class_recall"],
                          "correct_reversals": scored[
                              "complete_source_sensitive_parent_fix_reversals"],
                          "independent_gold": 0}, sort_keys=True))
        return 0
    except (SourceShortcutError, legacy.ScorecardError,
            OSError, ValueError, TypeError, KeyError, IndexError) as exc:
        parser.exit(1, "FALSUM PUBLIC SOURCE BENCHMARK V2 BLOCKED: "
                    + str(exc)[:250] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
