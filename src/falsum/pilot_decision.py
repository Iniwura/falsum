"""Fail-closed analysis of a real, but unreviewed, Telegraph V2 model pilot.

A PASS on six GHSA comparisons is not evidence of contextual code-review
generalization. This module audits the *actual* saved reports and records the
security-relevant failure modes. It never authorizes model registration.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from pathlib import Path

INTENT = "SECURITY_REVIEW_GENERAL"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
SPLITS = ("train", "validation", "holdout")


class PilotDecisionError(ValueError):
    """Reject missing, contradictory, or untrustworthy model evidence."""


def _object(value: object, name: str) -> dict:
    if not isinstance(value, dict):
        raise PilotDecisionError(f"{name} must be an object")
    return value


def _integer(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise PilotDecisionError(f"{name} must be an integer >= {minimum}")
    return value


def _fraction(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value) or not 0 <= value <= 1:
        raise PilotDecisionError(f"{name} must be a finite fraction in [0, 1]")
    return float(value)


def _finite(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise PilotDecisionError(f"{name} must be a finite numeric score")
    return float(value)


def _hash(value: object, name: str) -> None:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise PilotDecisionError(f"{name} must contain an actual SHA-256 digest")


def analyze(official: dict, counterfactual: dict, pilot: dict) -> dict:
    """Produce evidence-checked research diagnosis; never network eligibility."""
    official = _object(official, "official result")
    counterfactual = _object(counterfactual, "counterfactual report")
    pilot = _object(pilot, "pilot manifest")
    if (official.get("intent") != INTENT or counterfactual.get("intent") != INTENT
            or pilot.get("intent") != INTENT):
        raise PilotDecisionError("intent mismatch across training and scoring")
    if (pilot.get("research_only") is not True or pilot.get("network_eligible") is not False
            or pilot.get("training_authorized_for_submission") is not False
            or pilot.get("human_reviews") != 0):
        raise PilotDecisionError("pilot is not explicitly unreviewed/quarantined")
    if (counterfactual.get("status") != "UNREVIEWED_RESEARCH_BENCHMARK"
            or counterfactual.get("not_network_eligible") is not True
            or counterfactual.get("model_training_provenance_verified") is not False
            or counterfactual.get("model_artifact_integrity_verified") is not True):
        raise PilotDecisionError("counterfactual research provenance flags are inconsistent")
    for field in ("benchmark_sha256", "casebook_sha256"):
        _hash(counterfactual.get(field), field)
    artifact = _object(counterfactual.get("adapter_artifact"), "adapter artifact")
    _hash(artifact.get("sha256"), "adapter artifact digest")
    if artifact.get("integrity") != "SHA256_OF_LOCAL_FILES_ONLY":
        raise PilotDecisionError("adapter integrity statement is missing")

    partitions = _object(pilot.get("partitions"), "pilot partitions")
    for split in SPLITS:
        part = _object(partitions.get(split), f"pilot {split}")
        _integer(part.get("cases"), f"pilot {split} count", minimum=1)
        _hash(part.get("sha256"), f"pilot {split} hash")
    if official.get("base_model") != "answerdotai/ModernBERT-base":
        raise PilotDecisionError("official result does not name pinned model architecture")
    if official.get("train_pairs") != partitions["train"]["cases"]:
        raise PilotDecisionError("official training count disagrees with audited inputs")
    if official.get("n_eval") != partitions["holdout"]["cases"] or official.get("gate_split") != "test":
        raise PilotDecisionError("official holdout is not the audited test split")
    official_accuracy = _fraction(official.get("pairwise_accuracy"), "official pairwise accuracy")
    if official.get("verdict") not in ("PASS", "FAIL"):
        raise PilotDecisionError("official trainer verdict missing or invalid")

    scores = counterfactual.get("case_scores")
    if not isinstance(scores, list) or not scores:
        raise PilotDecisionError("real case-level model scores are required")
    splits = _object(counterfactual.get("splits"), "counterfactual split reports")
    ablations = _object(counterfactual.get("answer_only_ablation"), "answer-only ablation")
    family_rows = defaultdict(list)
    cases_per_split = defaultdict(list)
    ids = set()
    for row in scores:
        row = _object(row, "case score")
        case_id, split, group = row.get("case_id"), row.get("split"), row.get("rule_family")
        if not isinstance(case_id, str) or not case_id or case_id in ids:
            raise PilotDecisionError("duplicate or missing scored case id")
        ids.add(case_id)
        if split not in SPLITS or not isinstance(group, str) or not group:
            raise PilotDecisionError(f"{case_id}: invalid split/family")
        chosen = _finite(row.get("score_chosen"), f"{case_id} chosen")
        rejected = _finite(row.get("score_rejected"), f"{case_id} rejected")
        margin = _finite(row.get("margin"), f"{case_id} margin")
        _finite(row.get("ablated_margin"), f"{case_id} answer-only margin")
        if not math.isclose(chosen - rejected, margin, abs_tol=1e-6, rel_tol=1e-6):
            raise PilotDecisionError(f"{case_id}: margin contradicts raw scores")
        cases_per_split[split].append(row)
        family_rows[group].append(row)

    if counterfactual.get("case_count") != len(scores) or counterfactual.get("rule_families") != len(family_rows):
        raise PilotDecisionError("counterfactual case/family count mismatch")
    for split in SPLITS:
        part = _object(splits.get(split), f"counterfactual {split}")
        abl = _object(ablations.get(split), f"answer-only {split}")
        rows = cases_per_split[split]
        if not rows:
            raise PilotDecisionError(f"missing counterfactual {split}")
        wins = sum(r["margin"] > 0 for r in rows)
        ties = sum(r["margin"] == 0 for r in rows)
        for name, expected in (("count", len(rows)), ("wins", wins), ("ties", ties),
                               ("losses", len(rows) - wins - ties)):
            if part.get(name) != expected or isinstance(part.get(name), bool):
                raise PilotDecisionError(f"{split}: {name} contradicts individual model scores")
        if not math.isclose(_fraction(part.get("pairwise_fraction"), f"{split} fraction"),
                            (wins + 0.5 * ties) / len(rows), abs_tol=1e-5):
            raise PilotDecisionError(f"{split}: reported accuracy contradicts case scores")
        ab_wins = sum(r["ablated_margin"] > 0 for r in rows)
        ab_ties = sum(r["ablated_margin"] == 0 for r in rows)
        if (abl.get("count") != len(rows) or abl.get("wins") != ab_wins
                or abl.get("ties") != ab_ties or abl.get("losses") != len(rows) - ab_wins - ab_ties):
            raise PilotDecisionError(f"{split}: ablation counts contradict individual scores")

    families = _object(counterfactual.get("counterfactual_families"), "family reports")
    if set(families) != set(family_rows):
        raise PilotDecisionError("family report omits scored families")
    summary = {}
    for group, rows in sorted(family_rows.items()):
        if len(rows) != 2 or rows[0]["split"] != rows[1]["split"]:
            raise PilotDecisionError(f"{group}: expected exactly two contexts in the same split")
        stated = _object(families[group], f"{group} family")
        both = all(r["margin"] > 0 for r in rows)
        margins = stated.get("margins")
        if (stated.get("split") != rows[0]["split"]
                or stated.get("both_contexts_correct") is not both
                or not isinstance(margins, list) or len(margins) != 2
                or any(not math.isclose(_finite(a, f"{group} margin"), r["margin"], abs_tol=1e-6)
                       for a, r in zip(margins, rows))):
            raise PilotDecisionError(f"{group}: family report contradicts scored rows")
        summary[group] = {"split": rows[0]["split"], "both_contexts_correct": both,
                          "worst_margin": min(r["margin"] for r in rows)}

    release_blockers = [
        "No independent AppSec reviews of generated examples",
        "Fictional counterfactual examples are not verified real-world security ground truth",
        "Official holdout contains only six comparisons; PR holdout contains only two",
        "No independently verified model training provenance or ONNX/WASM/network execution",
    ]
    failed_families = [name for name, x in summary.items() if not x["both_contexts_correct"]]
    if failed_families:
        release_blockers.insert(0, "Real model fails at least one context in " + str(len(failed_families)) + " of " + str(len(summary)) + " counterfactual families")
    return {
        "schema_version": 1,
        "status": "BLOCKED_RESEARCH_ONLY",
        "network_eligible": False,
        "registration_authorized": False,
        "intent": INTENT,
        "official_training": {"verdict": official["verdict"], "test_pairs": official["n_eval"],
                              "pairwise_accuracy": official_accuracy},
        "research_counterfactual": {
            "total_cases": len(scores), "total_families": len(summary),
            "families_correct_in_both_contexts": len(summary) - len(failed_families),
            "failed_family_ids": failed_families,
            "validation_pairwise_accuracy": splits["validation"]["pairwise_fraction"],
            "holdout_pairwise_accuracy": splits["holdout"]["pairwise_fraction"],
            "validation_answer_only_accuracy": ablations["validation"]["pairwise_fraction"],
            "holdout_answer_only_accuracy": ablations["holdout"]["pairwise_fraction"],
            "families": summary,
        },
        "adapter_sha256": artifact["sha256"],
        "release_blockers": release_blockers,
        "next_experiment": "Obtain independent AppSec ground truth; train context-sensitive pairs from training-only families and compare against unchanged validation and holdout.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit research-only real-model results, NEVER authorize submission")
    parser.add_argument("--official", required=True, type=Path)
    parser.add_argument("--counterfactual", required=True, type=Path)
    parser.add_argument("--pilot", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        inputs = [json.loads(p.read_text(encoding="utf-8"))
                  for p in (args.official, args.counterfactual, args.pilot)]
        report = analyze(*inputs)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.output.exists():
            raise PilotDecisionError("refusing to replace existing pilot decision")
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (PilotDecisionError, OSError, ValueError, TypeError) as exc:
        parser.exit(1, f"FALSUM PILOT DECISION ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
