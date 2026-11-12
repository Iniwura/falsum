"""Fail-closed audit of actual Phase 4A old-model failure, never release authorization.

The ledger records genuine official Foundation score f32 bitstrings from a real
GitHub Actions run. It must not be confused with synthetic unit-test scoring.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct

from .phase4a_real_model_probe import CASE_PINS, MODEL_SHA, FOUNDATION_SHA, TOKENIZER_SHA256, SOURCE_SHA256

STATUS = "PHASE4A_GENUINE_SOURCE_BOUND_ORIGINAL_MODEL_NO_CONTEXT_REVERSALS"
LEDGER_PATH = "evidence/phase4a-2026-11-12-real-original-model-failure.json"
SOURCE_URL = "https://github.com/Iniwura/falsum/actions/runs/43289770022"
ARTIFACT_URL = "https://github.com/Iniwura/falsum/actions/runs/43289770022/artifacts/13976527819"
RESULT_HASH = "9a7dc55b7838fba00504663ea2a06fba3fddb8b344f003f5c57565af0d8361df"
INPUTS_HASH = "9023acda72512b215b2000e8ce88daae1c7f1abc692c0d4b6892f297745d9463"


class LedgerMismatch(ValueError):
    pass


def must(condition: bool, reason: str):
    if not condition:
        raise LedgerMismatch(reason)


def model_float(bits: str) -> float:
    must(isinstance(bits, str)
         and re.fullmatch(r"0x[0-9a-f]{8}", bits) is not None, "bad real score bits")
    f = struct.unpack(">f", bytes.fromhex(bits[2:]))[0]
    must(math.isfinite(f), "nonfinite score")
    return f


def check(ledger: dict, output: dict | None = None) -> dict:
    must(isinstance(ledger, dict)
         and ledger.get("schema_version") == 1
         and ledger.get("status") == STATUS
         and ledger.get("verified_date_utc") == "2026-11-12"
         and ledger.get("source_workflow") == SOURCE_URL
         and ledger.get("scoring_artifact") == ARTIFACT_URL
         and ledger.get("source_report_sha256") == SOURCE_SHA256
         and ledger.get("actual_results_json_sha256") == RESULT_HASH
         and ledger.get("frozen_inputs_sha256") == INPUTS_HASH
         and ledger.get("original_model_sha256") == MODEL_SHA
         and ledger.get("foundation_sha256") == FOUNDATION_SHA
         and ledger.get("official_tokenizer_sha256") == TOKENIZER_SHA256,
         "unverified source, model, Foundation or run identity")
    truth = {
        "original_model_unchanged": True,
        "source_catalogue_not_expert_security_labels": True,
        "public_cases_not_blind_holdout": True,
        "public_cases_not_known_model_pretraining_disjoint": True,
        "expert_adjudicated_labels": 0,
        "new_anjoman_rows": 0,
        "network_accuracy_certified": False,
        "registered_adapter": False,
        "automatic_registration_authorized": False,
        "original_model_release_veto": True,
        "model_improvement_demonstrated": False,
        "website_ui_changed": False,
    }
    must(ledger.get("truth_boundaries") == truth, "research-only truth boundaries were promoted")
    score_bits = ledger.get("score_hex_by_input")
    expected_ids = [c[0].replace(".", "-") + "--" + a
                    for c in CASE_PINS for a in "AB"]
    must(isinstance(score_bits, dict) and set(score_bits) == set(expected_ids)
         and len(expected_ids) == 12 and len(score_bits) == 12,
         "missing, duplicate or extra source-tied score evidence")
    predictions = []
    by_case = {}
    for case_id, pkg, version, ghsa, expected in CASE_PINS:
        a = model_float(score_bits[case_id.replace(".", "-")+"--A"])
        b = model_float(score_bits[case_id.replace(".", "-")+"--B"])
        choice = "A" if a > b else "B" if b > a else "TIE"
        predictions.append(choice)
        by_case[case_id] = (choice, a-b)
    truth_answers = [c[-1] for c in CASE_PINS]
    matches = sum(a == b for a, b in zip(predictions, truth_answers))
    pairs = [(CASE_PINS[i][1], predictions[i] != predictions[i+1]
              and "TIE" not in (predictions[i], predictions[i+1]),
              predictions[i] == truth_answers[i]
              and predictions[i+1] == truth_answers[i+1])
             for i in (0, 2, 4)]
    must(ledger.get("observed_choice_sequence") == predictions == ["A"]*6
         and ledger.get("source_fact_expected_sequence") == truth_answers == ["A", "B"]*3
         and ledger.get("source_fact_matches") == matches == 3
         and ledger.get("complete_version_reversals") == sum(x[2] for x in pairs) == 0
         and ledger.get("changed_model_preferences") == sum(x[1] for x in pairs) == 0
         and ledger.get("constant_a_baseline_matches") == 3
         and ledger.get("constant_b_baseline_matches") == 3
         and ledger.get("actual_model_score_inputs") == 12
         and ledger.get("actual_repeated_foundation_inference_calls") == 24,
         "actual 3/6, 0/3 negative model outcome is inconsistent or misreported")
    if output is not None:
        must(isinstance(output, dict)
             and output.get("status")
                == "PHASE4A_REAL_ORIGINAL_LORA_PUBLIC_VERSION_FACTS_DIAGNOSTIC_ONLY"
             and output.get("actual_official_foundation_inference") is True
             and output.get("actual_score_hex_by_input") == score_bits
             and output.get("catalogue_fact_matches") == 3
             and output.get("complete_version_fact_reversals") == 0
             and output.get("model_preference_reversal_count") == 0
             and output.get("genuine_model_score_inputs") == 12
             and output.get("genuine_repeated_inference_calls") == 24
             and output.get("pinned_source_report_sha256") == SOURCE_SHA256
             and output.get("frozen_inputs_sha256") == INPUTS_HASH
             and output.get("original_quarantined_model_sha256") == MODEL_SHA
             and output.get("official_foundation_sha256") == FOUNDATION_SHA
             and output.get("official_tokenizer_sha256") == TOKENIZER_SHA256
             and output.get("constant_A_baseline_matches") == 3
             and output.get("constant_B_baseline_matches") == 3
             and output.get("not_blind_or_private_holdout") is True
             and output.get("independent_expert_labels") == 0
             and output.get("new_anjoman_evaluation_rows") == 0
             and output.get("registered_evaluator") is False
             and output.get("network_accuracy_certified") is False
             and output.get("automatic_registration_permitted") is False
             and output.get("model_release_veto_remains") is True,
             "actual official report is incompatible with frozen real score evidence")
        cases = output.get("predictions")
        must(isinstance(cases, list) and len(cases) == 6,
             "actual per-case report incomplete")
        for case, pin in zip(cases, CASE_PINS):
            ident, pkg, version, ghsa, expected = pin
            choice, margin = by_case[ident]
            must(case == {
                "case_id": ident, "source_package": pkg,
                "catalogue_expected": expected, "model_preferred": choice,
                "margin_a_minus_b": margin,
                "matched_catalogue_fact": choice == expected,
            }, "actual model f32 margin/prediction changed: " + ident)
        groups = output.get("version_reversals")
        must(isinstance(groups, list) and len(groups) == 3,
             "missing source-fact reversal results")
        for group, (pkg, changed, correct) in zip(groups, pairs):
            must(group == {
                "package": pkg,
                "source_version_fact_reverses": True,
                "model_preference_reverses": changed,
                "both_catalogue_facts_matched": correct,
            }, "actual model reversal misrepresented")
    return {"observed_matches": matches,
            "complete_version_reversals": sum(x[2] for x in pairs),
            "actual_score_bits": 12, "release_authorized": False}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Verify real failed Phase 4A source scoring evidence")
    p.add_argument("--ledger", required=True, type=Path)
    p.add_argument("--report", type=Path)
    args = p.parse_args(argv)
    try:
        ledger = json.loads(args.ledger.read_text())
        report = None
        if args.report:
            raw = args.report.read_bytes()
            must(hashlib.sha256(raw).hexdigest() == RESULT_HASH,
                 "real official result bytes no longer match original immutable source run")
            report = json.loads(raw)
        result = check(ledger, report)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, struct.error) as err:
        p.exit(1, "FALSUM REAL MODEL FAILURE EVIDENCE MISMATCH: " + str(err) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
