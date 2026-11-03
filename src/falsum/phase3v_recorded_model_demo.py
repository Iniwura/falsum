"""Phase 3V: preserve and explain *recorded* real evaluator-model decisions.

This is NOT live inference. These are exact scores recorded from Phase 3J's
pinned official Telegraph Foundation/WASI/ONNX+LoRA CI experiment. Candidate
reviews are researcher-authored public strings and the provisional expected
ranking is from already-studied historical library-runtime observations.

No network calls, confidential evaluation rows, wallet, training or model
downloads are needed to inspect this evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
from pathlib import Path

from .phase3j_inputs import FAMILIES, proof as anchored_runtime_proof

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_PATH = ROOT / "evidence/phase3j-2026-11-02.json"
TEMPLATE_PATH = Path(__file__).with_name("templates") / "phase3v_recorded_model_demo.html"

STATUS = "RECORDED_OFFICIAL_FOUNDATION_MODEL_SCORES_RESEARCH_FAILURE_NOT_LIVE"
MODEL_SHA256 = "3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc"
MODEL_CI = "https://github.com/Iniwura/falsum/actions/runs/41411984601"


class RecordedModelEvidenceError(ValueError):
    """Stop rather than publish tampered scores, false labels or invented proof."""


def _float_from_bits(bits: str) -> float:
    if not isinstance(bits, str) or len(bits) != 10 or not bits.startswith("0x"):
        raise RecordedModelEvidenceError("invalid actual float32 score bits")
    try:
        raw = int(bits[2:], 16)
    except ValueError as exc:
        raise RecordedModelEvidenceError("malformed float32 bits") from exc
    value = struct.unpack(">f", struct.pack(">I", raw))[0]
    if not math.isfinite(value):
        raise RecordedModelEvidenceError("non-finite actual float32 model score")
    return value


def capture(root: Path = ROOT) -> dict:
    source = root / "evidence/phase3j-2026-11-02.json"
    data = json.loads(source.read_text(encoding="utf-8"))
    observed = data["observed"]
    if (
        data.get("schema_version") != 1
        or data.get("status") != "PHASE3J_VERIFIED_REAL_FOUNDATION_MODEL_KNOWN_FAMILY_CONTEXT_FAILURE_NOT_HOLDOUT"
        or data.get("original_model_sha256") != MODEL_SHA256
        or data.get("real_scoring_ci") != MODEL_CI
        or data.get("real_ci_job_conclusion") != "success"
        or data.get("original_model_retrained_in_phase") is not False
        or data.get("registered_evaluator") is not False
        or data.get("network_eligible") is not False
        or data.get("automatic_model_registration_permitted") is not False
        or data.get("blind_untouched_holdout") is not False
        or data.get("independent_expert_labels") != 0
        or observed.get("genuine_input_scores") != 8
        or observed.get("repeated_inference_calls") != 16
        or observed.get("human_provisional_preference_contexts") != 4
        or observed.get("contexts_matching_researcher_provisional_runtime_rules") != 2
        or observed.get("families_tested") != 2
        or observed.get("families_reversing_on_changed_runtime_fact") != 0
        or observed.get("families_matching_both_researcher_provisional_runtime_rules") != 0
    ):
        raise RecordedModelEvidenceError("refuse unverified or promotion-misrepresented model evidence")

    anchor = anchored_runtime_proof(root)
    score_bits = observed.get("float32_score_bits_by_input")
    records = observed.get("families")
    if (
        not isinstance(score_bits, dict)
        or len(score_bits) != 8
        or not isinstance(records, list)
        or len(records) != 2
        or [r.get("family") for r in records] != [f["id"] for f in FAMILIES]
    ):
        raise RecordedModelEvidenceError("actual model score recording is incomplete")

    families = []
    expected_keys = set()
    for original, recorded in zip(FAMILIES, records):
        contexts = []
        if len(original["contexts"]) != 2 or len(original["answers"]) != 2:
            raise RecordedModelEvidenceError("historical model input contract changed")
        if len(recorded.get("contexts", [])) != 2 or recorded.get("ranking_reversed") is not False:
            raise RecordedModelEvidenceError("recorded model context status was tampered")
        for (ctx_name, question, expected), actual in zip(original["contexts"], recorded["contexts"]):
            if actual.get("context") != ctx_name:
                raise RecordedModelEvidenceError("score context identity changed")
            answers = []
            for answer_id, authored_text in original["answers"]:
                key = original["id"] + "--" + ctx_name + "--" + answer_id
                expected_keys.add(key)
                bits = score_bits.get(key)
                value = _float_from_bits(bits)
                answers.append({
                    "id": answer_id, "text": authored_text,
                    "score_float32": value, "score_hex": bits,
                    "authored_not_model_generated": True
                })
            scores = [a["score_float32"] for a in answers]
            if scores[0] == scores[1]:
                raise RecordedModelEvidenceError("tie not supported in the real recording")
            winner = answers[0]["id"] if scores[0] > scores[1] else answers[1]["id"]
            if (
                winner != actual.get("model_preferred")
                or expected != actual.get("provisional_runtime_expected")
                or (winner == expected) is not actual.get("matched_provisional")
                or abs(scores[0] - actual.get("score_first_answer_f32", 999)) > 1e-7
                or abs(scores[1] - actual.get("score_second_answer_f32", 999)) > 1e-7
                or abs(scores[0] - scores[1] - actual.get("margin_first_minus_second", 999)) > 1e-7
            ):
                raise RecordedModelEvidenceError("float32 scores disagree with reported real model decisions")
            contexts.append({
                "id": ctx_name, "question": question,
                "provisional_expected": expected, "model_selected": winner,
                "model_matches_provisional": winner == expected,
                "candidate_answers": answers,
                "runtime_evidence_url": anchor["phase3h_runtime_workflow"] if original["id"] == "starlette-path-boundary"
                    else anchor["phase3i_runtime_workflow"],
                "independent_expert_adjudication": False,
            })
        if contexts[0]["model_selected"] != contexts[1]["model_selected"]:
            raise RecordedModelEvidenceError("published diagnostics did not reverse; don't invent improvement")
        if recorded.get("both_contexts_matched") is not False:
            raise RecordedModelEvidenceError("false family context-accuracy claim")
        families.append({
            "id": original["id"],
            "title": "Starlette / static file boundary" if original["id"] == "starlette-path-boundary"
                else "Requests / proxy authentication",
            "advisory": original["advisory"],
            "contexts": contexts,
            "same_candidate_selected_in_both_contexts": True
        })
    if set(score_bits) != expected_keys:
        raise RecordedModelEvidenceError("extra model scores or missing known input")
    if sum(c["model_matches_provisional"] for f in families for c in f["contexts"]) != 2:
        raise RecordedModelEvidenceError("unverified aggregate context-match count")

    return {
        "schema_version": 1, "status": STATUS,
        "purpose": "Inspect real previously recorded evaluator model decisions against public historical runtime observations.",
        "recorded_inference_not_live": True, "candidate_answers_researcher_authored": True,
        "input_families_known_and_not_blind": True, "labels_provisional_not_expert_approved": True,
        "independent_expert_labels": 0, "model_registered": False,
        "security_accuracy_certified": False, "user_private_eligible_pool_rows_used": False,
        "this_is_not_a_new_network_contribution": True,
        "source_record_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "model_package_sha256": MODEL_SHA256,
        "official_inference_workflow": MODEL_CI,
        "installed_library_verification": anchor,
        "recorded_actual_model_inference_calls": 16,
        "unique_model_scored_inputs": 8, "contexts": 4,
        "provisional_context_matches": 2,
        "families_with_correct_changed_fact_reversal": 0,
        "families": families,
        "notice": "Actual frozen model scores, not generated AI answers. Both alternatives were authored by researchers. Comparisons rely on previously studied source facts, NOT expert-adjudicated blind holdout labels or an active network evaluator."
    }


def render(report: dict, root: Path = ROOT) -> str:
    template = (root / "src/falsum/templates/phase3v_recorded_model_demo.html").read_text(encoding="utf-8")
    marker = "__REAL_RECORDED_MODEL_DATA__"
    if template.count(marker) != 1:
        raise RecordedModelEvidenceError("exactly one inert JSON data marker required")
    blob = json.dumps(report, separators=(",", ":"), ensure_ascii=False)
    for source, replacement in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e")):
        blob = blob.replace(source, replacement)
    return template.replace(marker, blob)


def write(out: Path, report: dict, root: Path = ROOT) -> None:
    if out.exists() or out.is_symlink():
        raise RecordedModelEvidenceError("output directory must be new; refuse overwriting evidence")
    html = render(report, root)
    out.mkdir(parents=True)
    (out / "index.html").write_text(html, encoding="utf-8")
    (out / "recorded-model-evidence.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Rebuild public judge preview from previously recorded *real* model scores")
    parser.add_argument("--out-dir", type=Path, required=True)
    opts = parser.parse_args(argv)
    report = capture()
    write(opts.out_dir, report)
    print(json.dumps({
        "status": report["status"],
        "unique_real_scored_inputs": report["unique_model_scored_inputs"],
        "recorded_model_inferences": report["recorded_actual_model_inference_calls"],
        "provisional_matches": str(report["provisional_context_matches"]) + "/4",
        "correct_context_reversal_families": "0/2",
        "live_model_executed_now": False,
        "output": str(opts.out_dir / "index.html")
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
