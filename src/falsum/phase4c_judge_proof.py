"""Judge-facing, static display of authentic *recorded* FALSUM scoring.

This is not live inference, general security accuracy, an independent expert
benchmark, a network registered evaluator or a claim that fixes prevent all risk.
The public synthetic learning lab remains unchanged at the root URL.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase4a_recorded_evidence import check as check_real, model_float
from .phase4a_real_model_probe import CASE_PINS, SOURCE_SHA256, score_id

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence/phase4a-2026-11-12-real-original-model-failure.json"
RECEIPT = ROOT / "evidence/phase3z-2026-11-12-pinned-real-advisory-receipt.json"
TEMPLATE = Path(__file__).with_name("templates") / "phase4c_judge_model_proof.html"
STATUS = "PHASE4C_STATIC_AUTHENTIC_RECORDED_MODEL_EVIDENCE_NOT_A_LIVE_EVALUATOR"
MODEL_RUN = "https://github.com/Iniwura/falsum/actions/runs/43291803205"
SOURCE_RUN = "https://github.com/Iniwura/falsum/actions/runs/43287674960"
CHECKER_RUN = "https://github.com/Iniwura/falsum/actions/runs/43297345188"


class JudgeProofError(ValueError):
    pass


def require(ok: bool, message: str):
    if not ok:
        raise JudgeProofError(message)


def read_validated(root: Path = ROOT) -> dict:
    raw_ledger = (root / EVIDENCE.relative_to(ROOT)).read_bytes()
    raw_receipt = (root / RECEIPT.relative_to(ROOT)).read_bytes()
    ledger = json.loads(raw_ledger)
    receipt = json.loads(raw_receipt)
    check_real(ledger)
    require(receipt.get("schema_version") == 1
            and receipt.get("pinned_advisory_database_commit")
                == "b2a0c7d47ab94089f8774eacdc65ad80f2457170"
            and receipt.get("source_artifact_report_sha256") == SOURCE_SHA256
            and receipt.get("observed_case_count") == 6
            and receipt.get("verified_distinct_source_package_count") == 3
            and receipt.get("verified_affected_fixed_reversal_groups") == 3
            and receipt.get("observed_correct_catalogue_order") == ["A", "B"]*3
            and receipt.get("actual_model_scoring_run") is False
            and receipt.get("external_human_expert_review_count") == 0
            and receipt.get("registered_evaluator") is False
            and receipt.get("training_allowed") is False,
            "Phase 3Z source receipt changed or is falsely promoted")
    records = receipt.get("source_release_facts")
    require(isinstance(records, list) and len(records) == 3
            and [r.get("package") for r in records] ==
                ["docling-core", "hydra-core", "python-multipart"],
            "unexpected package provenance order")
    cases = []
    bits = ledger["score_hex_by_input"]
    for k, row in enumerate(records):
        before, after = CASE_PINS[k*2:k*2+2]
        package, ghsa, vulnerable, fixed = (
            row["package"], row["advisory"],
            row["affected_release"], row["fixed_release"])
        require((before[1], before[2], before[3], before[4])
                    == (package, vulnerable, ghsa, "A")
                and (after[1], after[2], after[3], after[4])
                    == (package, fixed, ghsa, "B"),
                "recorded release facts do not agree with scoring input pin")
        versions = []
        for pin in (before, after):
            case_id, _, version, _, correct = pin
            a, b = bits[score_id(case_id, "A")], bits[score_id(case_id, "B")]
            a_value, b_value = model_float(a), model_float(b)
            model = "A" if a_value > b_value else "B" if b_value > a_value else "TIE"
            require(model == "A" and correct in ("A", "B"),
                    "original Phase4A model-choice evidence has drifted")
            versions.append({
                "version": version, "source_expected": correct,
                "source_fact": "Within this GHSA range" if correct == "A"
                                else "Outside this GHSA range",
                "model_selected": model, "model_match": model == correct,
                "score_a": round(a_value, 7),
                "score_b": round(b_value, 7),
                "score_a_f32_bits": a, "score_b_f32_bits": b,
                "score_margin_a_minus_b": round(a_value - b_value, 7),
            })
        cases.append({
            "project": package, "ghsa": ghsa,
            "ghsa_url": "https://github.com/advisories/" + ghsa,
            "affected_release": vulnerable, "fixed_release": fixed,
            "versions": versions, "correct_reversal": False,
        })
    require(len(cases) == 3
            and sum(r["model_match"] for c in cases for r in c["versions"]) == 3,
            "three-of-six recorded model failure no longer reproducible")
    return {
        "schema_version": 1,
        "status": STATUS,
        "original_unchanged_quarantined_model": True,
        "recorded_inference_not_live": True,
        "model_registered_to_telegraph": False,
        "training_performed_in_this_page": False,
        "independently_expert_adjudicated": False,
        "not_blind_holdout": True,
        "model_security_accuracy_certified": False,
        "source_limit": "Version inclusion in exactly one pinned public GHSA; not application exploitability or total safety.",
        "real_model_score_inputs": 12,
        "real_repeated_foundation_inferences": 24,
        "model_matches_narrow_source_facts": 3,
        "model_matches_total": 6,
        "complete_factual_reversals": 0,
        "reversal_groups_total": 3,
        "constant_A_baseline": 3,
        "constant_B_baseline": 3,
        "source_receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
        "authentic_model_ledger_sha256": hashlib.sha256(raw_ledger).hexdigest(),
        "frozen_source_report_sha256": SOURCE_SHA256,
        "actual_model_scores_sha256": ledger["actual_results_json_sha256"],
        "model_run_url": MODEL_RUN,
        "source_run_url": SOURCE_RUN,
        "checker_run_url": CHECKER_RUN,
        "cases": cases,
    }


def render(report: dict, template: str) -> str:
    placeholder = "__FALSUM_REAL_EVIDENCE__"
    require(template.count(placeholder) == 1, "unsafe or missing inert data slot")
    require(report.get("status") == STATUS
            and len(report.get("cases", [])) == 3
            and report.get("model_registered_to_telegraph") is False
            and report.get("complete_factual_reversals") == 0,
            "reject marketing report without exact evidence")
    text = json.dumps(report, separators=(",", ":"), ensure_ascii=False)
    text = text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return template.replace(placeholder, text)


def write(out_dir: Path, root: Path = ROOT) -> dict:
    require(not out_dir.exists() and not out_dir.is_symlink(),
            "refuse to overwrite static evidence build")
    report = read_validated(root)
    template = (root / TEMPLATE.relative_to(ROOT)).read_text(encoding="utf-8")
    markup = render(report, template)
    out_dir.mkdir(parents=True)
    (out_dir / "index.html").write_text(markup, encoding="utf-8")
    (out_dir / "ACTUAL-RECORDED-FOUNDATION-MODEL-SCORES.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Build genuine recorded-model judge proof, NEVER active inference")
    p.add_argument("--out-dir", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        report = write(args.out_dir)
        print(json.dumps({
            "status": STATUS,
            "recorded_real_model_score_inputs": report["real_model_score_inputs"],
            "matches": report["model_matches_narrow_source_facts"],
            "complete_reversals": report["complete_factual_reversals"],
            "registered_evaluator": False,
            "output": str(args.out_dir / "index.html"),
        }, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError) as e:
        p.exit(1, "FALSUM RECORDING INTEGRITY BLOCKED: " + str(e) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
