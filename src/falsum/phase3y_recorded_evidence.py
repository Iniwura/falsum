"""Reconcile Phase 3Y's actual failed model scores. Never authorize training or registration."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import struct
from zipfile import ZipFile

from .phase3y_hard_model_probe import audit, GROUPS, SELECTED

STATUS = "PHASE3Y_REAL_MODEL_FAILED_ALL_CONTEXT_REVERSALS_RESEARCH_ONLY"
MODEL_SHA = "3d269cc080538b6a13ae8e5fbb8526921ffe9689c1a6f62f9a6161a9d4680fbc"
FOUNDATION_SHA = "0a49b325304bb4cf292e683929689d0457966be264f60bfc94d0072b614bf8e6"
TOKENIZER_SHA = "67bc76f8b9386efba1a761c1c8e5ad439fd0eaf1c2826e9dd1a205c7af4dc456"
FILES = (
    "source/axios-probe.json",
    "source/django-probe.json",
    "results/FROZEN-KNOWN-HARD-INPUTS.json",
    "results/ACTUAL-KNOWN-HARD-MODEL-RESULTS.json",
)

class EvidenceError(ValueError):
    pass

def require(ok, message):
    if not ok:
        raise EvidenceError(message)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def decode(bits):
    require(isinstance(bits, str) and len(bits) == 10 and bits.startswith("0x")
            and all(c in "0123456789abcdef" for c in bits[2:]), "invalid float32 bits")
    result = struct.unpack(">f", bytes.fromhex(bits[2:]))[0]
    require(math.isfinite(result), "non-finite score")
    return result

def check(record):
    require(isinstance(record, dict) and record.get("schema_version") == 1
            and record.get("status") == STATUS and record.get("date") == "2026-11-05"
            and record.get("source") == "https://github.com/Iniwura/falsum/actions/runs/42105873138"
            and record.get("artifact_url") == "https://github.com/Iniwura/falsum/actions/runs/42105873138/artifacts/13450729962", "untrusted run identity")
    require(record.get("truth_boundaries") == {
        "real_official_model_inference": True,
        "known_source_families_only": True,
        "human_approved_labels": 0,
        "new_network_rows": 0,
        "no_retraining": True,
        "model_registration_permitted": False,
        "model_quality_passed": False,
        "impact_on_production_ui": False,
        "existing_20_eligible_anjoman_rows_untouched": True,
    }, "unverified quality or release claim")
    report = record.get("verified_audit", {})
    required = {
        "schema_version":1,
        "status":"PHASE3Y_REAL_QUARANTINED_MODEL_HARD_SOURCE_DIAGNOSTIC_ONLY",
        "original_model_sha256": MODEL_SHA,
        "foundation_sha256": FOUNDATION_SHA,
        "official_tokenizer_sha256": TOKENIZER_SHA,
        "actual_official_foundation_inference": True,
        "real_score_inputs": 16,
        "real_inference_calls_including_repeats": 32,
        "prior_known_source_families": 2,
        "blind_holdout": False,
        "independent_expert_labels": 0,
        "network_eligible": False,
        "model_release_veto_remains": True,
        "registered_evaluator": False,
        "automatic_registration_permitted": False,
    }
    for name, val in required.items():
        require(type(report.get(name)) is type(val) and report.get(name) == val,
                "wrong model provenance/release boundary: " + name)
    require(isinstance(record.get("artifact_sha256"), str)
            and len(record["artifact_sha256"]) == 64
            and set(record.get("artifact_file_sha256", {})) == set(FILES),
            "missing complete CI archive provenance")
    for digest in record["artifact_file_sha256"].values():
        require(isinstance(digest, str) and len(digest) == 64
                and all(x in "0123456789abcdef" for x in digest), "invalid input digest")
    expected_ids = {name+"--"+answer for name in SELECTED for answer in ("A","B")}
    bits = record.get("score_bits_by_input", {})
    require(isinstance(bits, dict) and set(bits) == expected_ids, "missing or extra score bits")
    results = report.get("case_results")
    require(isinstance(results, list) and len(results) == 8, "changed case count")
    predicted = {}
    for name, row in zip(SELECTED, results):
        a, b = decode(bits[name+"--A"]), decode(bits[name+"--B"])
        winner = "A" if a > b else "B" if b > a else "TIE"
        require(row.get("case_id") == name
                and row.get("model_preferred") == winner
                and row.get("margin_a_minus_b") == a-b
                and row.get("source_executed_provisional_preference") in ("A","B")
                and row.get("matches_provisional") is (winner == row["source_executed_provisional_preference"]),
                "real float32 bits contradict recorded preference: " + name)
        predicted[name] = row
    require([x["source_executed_provisional_preference"] for x in results]
            == ["A","B","A","B","B","A","A","B"], "historical source facts changed")
    expected_groups = []
    for group, before, after in GROUPS:
        first, second = predicted[before], predicted[after]
        expected_groups.append({
            "group":group,
            "source_rule_reverses":True,
            "model_preference_reverses":first["model_preferred"] != second["model_preferred"] and
                "TIE" not in (first["model_preferred"], second["model_preferred"]),
            "both_source_rules_match":first["matches_provisional"] and second["matches_provisional"],
        })
    require(report.get("counterfactual_groups") == expected_groups, "counterfactual comparison was falsified")
    require(report.get("provisional_matches") == sum(r["matches_provisional"] for r in results) == 4
            and report.get("complete_provisional_reversals") == sum(g["both_source_rules_match"] for g in expected_groups) == 0,
            "known actual 4/8 and 0/4 failure changed")
    require(all(not g["model_preference_reverses"] for g in expected_groups)
            and report.get("constant_A_baseline_matches") == 4
            and report.get("constant_B_baseline_matches") == 4,
            "context insensitivity or trivial baselines misreported")
    return {"real_score_inputs":16, "repeat_verified_inferences":32,
            "provisional_matches":4, "complete_reversals":0, "registration_permitted":False}

def reconcile(record, read):
    for name in FILES:
        require(sha(read(name)) == record["artifact_file_sha256"][name],
                "source/result file hash mismatch: " + name)
    official = json.loads(read(FILES[-1]))
    require(official == record["verified_audit"], "official audited report mismatch")
    inputs = json.loads(read(FILES[2]))
    require(sha(json.dumps(inputs, sort_keys=True, separators=(",",":")).encode()) == official["frozen_inputs_sha256"]
            and len(inputs.get("inputs", [])) == 16
            and inputs.get("blind_holdout") is False, "tampered frozen scoring inputs")
    source_a = json.loads(read(FILES[0]))
    source_d = json.loads(read(FILES[1]))
    scores = {}
    for row in inputs["inputs"]:
        ident = row["id"]
        require(ident in record["score_bits_by_input"], "unrecognized model scoring input")
        packet = json.loads(read("results/"+ident+"/OFFICIAL-SCORE.json"))
        require(packet.get("score_hex") == record["score_bits_by_input"][ident],
                "actual score bit mismatch: " + ident)
        scores[ident] = packet
    # Reuse the real Phase 3Y auditor, which also checks original Foundation
    # manifests, source provenance, tokenizer framing, score identity and no release.
    from .phase3y_hard_model_probe import audit
    require(audit(inputs, scores, source_a, source_d) == official,
            "original model auditor did not reproduce the committed report")
    return check(record)

def main(argv=None):
    parser=argparse.ArgumentParser(description="Preserve real failed FALSUM counterfactual scores")
    parser.add_argument("--ledger", type=Path, required=True)
    choice=parser.add_mutually_exclusive_group()
    choice.add_argument("--archive", type=Path)
    choice.add_argument("--artifact-root", type=Path)
    args=parser.parse_args(argv)
    try:
        record=json.loads(args.ledger.read_text())
        result=check(record)
        if args.archive:
            require(sha(args.archive.read_bytes()) == record["artifact_sha256"], "ZIP archive changed")
            with ZipFile(args.archive) as archive:
                result=reconcile(record, archive.read)
        if args.artifact_root:
            root=args.artifact_root.resolve()
            result=reconcile(record, lambda name:(root/name).read_bytes())
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, struct.error) as err:
        parser.exit(1, "PHASE3Y EVIDENCE FAILED: " + str(err) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
