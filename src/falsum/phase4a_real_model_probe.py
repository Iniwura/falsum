"""Phase 4A: actual official Foundation scoring of six NEW public advisory-version cases.

Public source-catalogue diagnostics only: not a sealed project holdout, independent
security labels, deployment audit, improved model or network evaluator registration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from .phase3c_score_inputs import TOKENIZER_SHA256
from .phase3c_score_report import _score, ScoreProofError, MODEL_SHA, FOUNDATION_SHA
from .phase3y_hard_model_probe import render

STATUS = "PHASE4A_REAL_ORIGINAL_LORA_PUBLIC_VERSION_FACTS_DIAGNOSTIC_ONLY"
INPUT_STATUS = "PHASE4A_FROZEN_SIX_PUBLIC_GHSA_VERSION_CASES_NOT_BLIND"
SOURCE_SHA256 = "82347910cb443f2b1cbde565107dbbd280f40e884ca45f2abfd501a8a5d108a8"
SOURCE_STATUS = "PHASE3Z_REAL_PUBLIC_ADVISORY_VERSION_PAIRS_RESEARCH_ONLY"
CASE_PINS = (
    ("docling-core-2.48.3", "docling-core", "2.48.3", "GHSA-vqxf-v2gg-x3hc", "A"),
    ("docling-core-2.48.4", "docling-core", "2.48.4", "GHSA-vqxf-v2gg-x3hc", "B"),
    ("hydra-core-1.3.7", "hydra-core", "1.3.7", "GHSA-wf6j-7hvr-gr93", "A"),
    ("hydra-core-1.3.8", "hydra-core", "1.3.8", "GHSA-wf6j-7hvr-gr93", "B"),
    ("python-multipart-0.0.25", "python-multipart", "0.0.25", "GHSA-mj87-hwqh-73pj", "A"),
    ("python-multipart-0.0.26", "python-multipart", "0.0.26", "GHSA-mj87-hwqh-73pj", "B"),
)
ADVISORY_DIGESTS = (
    "7837586cf082bd918be2aaca15f6137c2e8b28ce9d953644197c8766d8e7540a",
    "9e3d1cb339b3e9eb177326d42f916216da755bb629eecc313170edb39fcbc3d2",
    "5d34e7e9046fc498499e11fa59fe87f9b0c09a67d4dae790c8bbe9f14342b9c7",
)
TOKEN_CAP = 256  # well under official 512, never truncate.
ID_RE = re.compile(r"^[a-z0-9-]+--[AB]$")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(text: str) -> str:
    return sha(text.encode("utf-8"))


def require(flag: bool, reason: str) -> None:
    if not flag:
        raise ValueError(reason)


def score_id(case_id: str, answer_id: str) -> str:
    ident = case_id.replace(".", "-") + "--" + answer_id
    require(ID_RE.fullmatch(ident) is not None, "unsafe score filename")
    return ident


def load_source(raw: bytes) -> dict:
    require(sha(raw) == SOURCE_SHA256,
            "Phase 3Z real GHSA/PyPI source artifact is NOT the immutable verified report")
    source = json.loads(raw)
    require(isinstance(source, dict)
            and source.get("schema_version") == 1
            and source.get("status") == SOURCE_STATUS
            and source.get("intent") == "SECURITY_REVIEW_GENERAL"
            and source.get("case_count") == 6
            and source.get("distinct_package_projects") == 3
            and source.get("catalogue_version_reversal_pairs") == 3
            and source.get("pinned_public_advisory_database_commit")
                == "b2a0c7d47ab94089f8774eacdc65ad80f2457170"
            and source.get("catalogue_source_verified_by_exact_git_blobs") is True
            and source.get("live_pypi_release_existence_checked") is True
            and source.get("model_scores_measured") is False
            and source.get("not_blind_or_private_holdout") is True
            and source.get("not_model_pretraining_disjoint") is True
            and source.get("not_independent_expert_reviewed") is True
            and source.get("independent_expert_labels") == 0
            and source.get("new_network_eligible_rows") == 0
            and source.get("registered_evaluator") is False
            and source.get("automatic_registration_permitted") is False
            and source.get("trainable_pairs") == [],
            "Phase 3Z source or no-release boundary changed")
    prov = source.get("provenance")
    require(isinstance(prov, list) and len(prov) == 3
            and [p.get("pinned_advisory_json_sha256") for p in prov]
                == list(ADVISORY_DIGESTS),
            "official advisory source digest mismatch")
    cases = source.get("cases")
    require(isinstance(cases, list) and len(cases) == 6, "missing version cases")
    for pin, case in zip(CASE_PINS, cases):
        ident, package, version, ghsa, expected = pin
        require(isinstance(case, dict)
                and (case.get("case_id"), case.get("source_package"),
                     case.get("source_release"), case.get("advisory"),
                     case.get("mechanically_source_derived_preference")) == pin
                and case.get("version_in_this_one_advisory_range") is (expected == "A")
                and case.get("public_catalogue_question_not_independent_expert_label") is True
                and case.get("model_score_measured") is False
                and case.get("training_authorized") is False
                and isinstance(case.get("question"), str)
                and len(case["question"]) > 80
                and isinstance(case.get("candidate_answers"), list)
                and [a.get("id") for a in case["candidate_answers"]] == ["A", "B"],
                "catalogue case facts were altered: " + ident)
        require(all(isinstance(a.get("text"), str) and a["text"]
                    for a in case["candidate_answers"]), "answer text is empty")
    for i in (0, 2, 4):
        require(cases[i]["candidate_answers"] == cases[i+1]["candidate_answers"],
                "before/after answers must remain identical")
    require(len({score_id(x["case_id"], "A") for x in cases}) == 6,
            "duplicate score identity")
    return source


def make_inputs(raw: bytes, tokenizer_bytes: bytes, encode) -> dict:
    source = load_source(raw)
    require(sha(tokenizer_bytes) == TOKENIZER_SHA256,
            "nonofficial tokenizer rejected")
    inputs = []
    for case in source["cases"]:
        for answer in case["candidate_answers"]:
            task = render(case["question"], answer["text"])
            ids = encode(task)
            require(isinstance(ids, list) and 8 <= len(ids) <= TOKEN_CAP
                    and ids[0] == 50281 and ids[-1] == 50282
                    and all(type(i) is int and 0 <= i < 50368 for i in ids),
                    "official tokenizer framing invalid, or token budget exceeded; no truncation")
            inputs.append({
                "id": score_id(case["case_id"], answer["id"]),
                "source_case_id": case["case_id"],
                "answer_id": answer["id"],
                "question_sha256": digest(case["question"]),
                "answer_sha256": digest(answer["text"]),
                "rendered_sha256": digest(task),
                "token_count": len(ids), "input_ids": ids,
                "source_catalogue_expected": case["mechanically_source_derived_preference"],
                "independently_adjudicated": False,
            })
    require(len(inputs) == 12 and len({r["id"] for r in inputs}) == 12,
            "expected 12 unique score inputs")
    return {
        "schema_version": 1, "status": INPUT_STATUS,
        "source_report_sha256": SOURCE_SHA256,
        "official_tokenizer_sha256": TOKENIZER_SHA256,
        "intent_family": "SECURITY_REVIEW",
        "intent": "SECURITY_REVIEW_GENERAL",
        "source_case_count": 6,
        "score_input_count": 12,
        "source_projects": 3,
        "source_boundaries_are_public_not_independent_labels": True,
        "blind_holdout": False,
        "independent_expert_labels": 0,
        "training_allowed": False,
        "network_eligible": False,
        "registered_evaluator": False,
        "inputs": inputs,
    }


def audit(raw: bytes, frozen: dict, scores: dict) -> dict:
    source = load_source(raw)
    require(isinstance(frozen, dict)
            and frozen.get("schema_version") == 1
            and frozen.get("status") == INPUT_STATUS
            and frozen.get("source_report_sha256") == SOURCE_SHA256
            and frozen.get("official_tokenizer_sha256") == TOKENIZER_SHA256
            and frozen.get("intent_family") == "SECURITY_REVIEW"
            and frozen.get("intent") == "SECURITY_REVIEW_GENERAL"
            and frozen.get("source_case_count") == 6
            and frozen.get("source_projects") == 3
            and frozen.get("score_input_count") == 12
            and frozen.get("source_boundaries_are_public_not_independent_labels") is True
            and frozen.get("blind_holdout") is False
            and frozen.get("independent_expert_labels") == 0
            and frozen.get("training_allowed") is False
            and frozen.get("network_eligible") is False
            and frozen.get("registered_evaluator") is False,
            "frozen input source or release claim altered")
    expected = [(c, a) for c in source["cases"] for a in c["candidate_answers"]]
    rows = frozen.get("inputs")
    require(isinstance(rows, list) and len(rows) == 12 and isinstance(scores, dict)
            and len(scores) == 12 and set(scores) ==
            {score_id(c["case_id"], a["id"]) for c, a in expected},
            "missing or duplicated actual score packets")
    decoded = {}
    score_bits = {}
    for row, (case, ans) in zip(rows, expected):
        ident = score_id(case["case_id"], ans["id"])
        require(isinstance(row, dict)
                and row.get("id") == ident
                and row.get("source_case_id") == case["case_id"]
                and row.get("answer_id") == ans["id"]
                and row.get("question_sha256") == digest(case["question"])
                and row.get("answer_sha256") == digest(ans["text"])
                and row.get("rendered_sha256") == digest(render(case["question"], ans["text"]))
                and row.get("source_catalogue_expected") ==
                    case["mechanically_source_derived_preference"]
                and row.get("independently_adjudicated") is False
                and isinstance(row.get("input_ids"), list)
                and type(row.get("token_count")) is int
                and 8 <= row["token_count"] <= TOKEN_CAP
                and len(row["input_ids"]) == row["token_count"]
                and row["input_ids"][0] == 50281
                and row["input_ids"][-1] == 50282
                and all(type(n) is int and 0 <= n < 50368
                        for n in row["input_ids"]),
                "source-to-token score binding failed for " + ident)
        verified = _score(scores[ident], ident)
        decoded[ident] = verified["float32_value"]
        score_bits[ident] = verified["float32_score_hex"]
    predictions = []
    for case in source["cases"]:
        a, b = decoded[score_id(case["case_id"], "A")], decoded[score_id(case["case_id"], "B")]
        preferred = "A" if a > b else "B" if b > a else "TIE"
        predictions.append({
            "case_id": case["case_id"],
            "source_package": case["source_package"],
            "catalogue_expected": case["mechanically_source_derived_preference"],
            "model_preferred": preferred,
            "margin_a_minus_b": a-b,
            "matched_catalogue_fact": preferred == case["mechanically_source_derived_preference"],
        })
    reversals = []
    for i in (0, 2, 4):
        before, after = predictions[i], predictions[i+1]
        reversals.append({
            "package": before["source_package"],
            "source_version_fact_reverses": True,
            "model_preference_reverses": before["model_preferred"] != after["model_preferred"]
                and "TIE" not in (before["model_preferred"], after["model_preferred"]),
            "both_catalogue_facts_matched": before["matched_catalogue_fact"]
                and after["matched_catalogue_fact"],
        })
    return {
        "schema_version": 1, "status": STATUS,
        "actual_official_foundation_inference": True,
        "original_quarantined_model_sha256": MODEL_SHA,
        "official_foundation_sha256": FOUNDATION_SHA,
        "official_tokenizer_sha256": TOKENIZER_SHA256,
        "pinned_source_report_sha256": SOURCE_SHA256,
        "frozen_inputs_sha256": sha(json.dumps(frozen, sort_keys=True, separators=(",", ":")).encode()),
        "genuine_model_score_inputs": 12, "genuine_repeated_inference_calls": 24,
        "source_package_projects": 3,
        "public_source_fact_comparisons": 6,
        "complete_version_fact_reversals": sum(p["both_catalogue_facts_matched"] for p in reversals),
        "model_preference_reversal_count": sum(p["model_preference_reverses"] for p in reversals),
        "catalogue_fact_matches": sum(p["matched_catalogue_fact"] for p in predictions),
        "constant_A_baseline_matches": 3, "constant_B_baseline_matches": 3,
        "predictions": predictions, "version_reversals": reversals,
        "actual_score_hex_by_input": score_bits,
        "previously_unstudied_package_projects_but_not_model_pretraining_disjoint": True,
        "not_blind_or_private_holdout": True,
        "independent_expert_labels": 0,
        "new_anjoman_evaluation_rows": 0,
        "network_accuracy_certified": False,
        "registered_evaluator": False,
        "automatic_registration_permitted": False,
        "model_release_veto_remains": True,
        "notice": (
            "Actual old LoRA scores compared to source-catalogue facts on 3 newly studied "
            "package projects. No human AppSec labels, blind evaluation, network acceptance, "
            "trained improvement, general security accuracy, or evaluator registration."
        ),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Score old quarantined LoRA on source-verified Phase 3Z version questions")
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--tokenizer", type=Path)
    p.add_argument("--inputs", type=Path)
    p.add_argument("--scores-dir", type=Path)
    args = p.parse_args(argv)
    try:
        if args.out.exists() or args.out.is_symlink():
            raise ValueError("refuse overwrite actual model score evidence")
        raw = args.source.read_bytes()
        if args.tokenizer is not None and args.inputs is None and args.scores_dir is None:
            from tokenizers import Tokenizer
            token_bytes = args.tokenizer.read_bytes()
            tokenizer = Tokenizer.from_str(token_bytes.decode("utf-8"))
            result = make_inputs(raw, token_bytes,
                                 lambda task: tokenizer.encode(task, add_special_tokens=True).ids)
            for row in result["inputs"]:
                pth = args.out.parent / ("SCORE-" + row["id"] + ".json")
                if pth.exists() or pth.is_symlink():
                    raise ValueError("score input would overwrite previous file")
            args.out.parent.mkdir(parents=True, exist_ok=True)
            for row in result["inputs"]:
                (args.out.parent / ("SCORE-" + row["id"] + ".json")).write_text(json.dumps({
                    "input_ids": row["input_ids"],
                    "attention_mask": [1]*row["token_count"]
                }, separators=(",", ":")) + "\n", encoding="utf-8")
        elif args.inputs is not None and args.scores_dir is not None and args.tokenizer is None:
            frozen = json.loads(args.inputs.read_text())
            require(isinstance(frozen, dict) and isinstance(frozen.get("inputs"), list),
                    "malformed untrusted frozen inputs")
            scores = {}
            for row in frozen["inputs"]:
                ident = row.get("id")
                require(isinstance(ident, str) and ID_RE.fullmatch(ident) is not None
                        and ident not in scores, "duplicate or unsafe score output path")
                scores[ident] = json.loads(
                    (args.scores_dir / ident / "OFFICIAL-SCORE.json").read_text())
            result = audit(raw, frozen, scores)
        else:
            raise ValueError("provide either --tokenizer OR --inputs AND --scores-dir")
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: v for k, v in result.items() if k in (
            "status", "genuine_model_score_inputs", "catalogue_fact_matches",
            "complete_version_fact_reversals", "automatic_registration_permitted"
        )}, indent=2))
        return 0
    except (ValueError, TypeError, KeyError, IndexError, OSError,
            ScoreProofError, UnicodeError) as exc:
        p.exit(1, "PHASE4A ACTUAL MODEL EVIDENCE ERROR: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
