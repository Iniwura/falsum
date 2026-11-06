"""Phase 3Y: reproducible REAL model-scoring inputs for eight known hard cases.

Only source-executed, researcher-provisional rules. Never a blind holdout,
independent security verdict, trainer export, network claim or model-release gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from .phase3x_hard_cases import build as build_hard, STATUS as HARD_STATUS
from .phase3c_score_inputs import TOKENIZER_SHA256
from .phase3c_score_report import _score, ScoreProofError, MODEL_SHA, FOUNDATION_SHA

STATUS = "PHASE3Y_REAL_QUARANTINED_MODEL_HARD_SOURCE_DIAGNOSTIC_ONLY"
INPUT_STATUS = "PHASE3Y_FROZEN_KNOWN_HARD_MODEL_INPUTS_NOT_A_BLIND_HOLDOUT"
# Counterfactual pairs, not cherry-picked model results. Both revisions are scored.
SELECTED = (
    "axios-01", "axios-02", "axios-07", "axios-08",
    "django-3601-parent", "django-3601-patched",
    "django-12-digit-leading-comma-parent", "django-12-digit-leading-comma-patched",
)
GROUPS = (
    ("axios-strict-absolute", "axios-01", "axios-02"),
    ("axios-strict-protocol-relative", "axios-07", "axios-08"),
    ("django-long-input", "django-3601-parent", "django-3601-patched"),
    ("django-leading-comma", "django-12-digit-leading-comma-parent", "django-12-digit-leading-comma-patched"),
)


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha(text: str) -> str:
    return sha_bytes(text.encode("utf-8"))


def render(question: str, answer: str) -> str:
    return "### Task:\n" + question + "\n\n### Answer:\n" + answer


def load_cases(axios: dict, django: dict) -> tuple[dict, list[dict]]:
    # This invokes Phase3X's exact source-result validation. It cannot by itself
    # certify that JSON came from upstream. CI supplies fixed, run-pinned artifacts.
    generated = build_hard(axios, django)
    if (generated.get("status") != HARD_STATUS
            or generated.get("question_count") != 18
            or generated.get("known_not_blind") is not True
            or generated.get("independent_human_labels") != 0
            or generated.get("actual_model_scoring_run") is not False
            or generated.get("trainable_pairs") != []
            or generated.get("network_eligible") is not False):
        raise ValueError("Phase3X source-only status or research boundary changed")
    by_id = {case["id"]: case for case in generated["cases"]}
    if len(by_id) != 18 or len(SELECTED) != 8 or set(SELECTED) - set(by_id):
        raise ValueError("Missing or duplicate selected source-grounded cases")
    cases = [by_id[key] for key in SELECTED]
    for case in cases:
        if (case.get("research_source_expected") not in {"A", "B"}
                or case.get("independent_expert_label") is not None
                or case.get("training_authorized") is not False
                or len(case.get("candidate_answers", [])) != 2
                or [a.get("id") for a in case["candidate_answers"]] != ["A", "B"]
                or not all(isinstance(a.get("text"), str) and a["text"] for a in case["candidate_answers"])
                or not isinstance(case.get("question"), str)):
            raise ValueError("Unreviewed binary hard-case conditions violated")
    for _, before, after in GROUPS:
        pair = [by_id[before], by_id[after]]
        if (pair[0]["research_source_expected"] == pair[1]["research_source_expected"]
                or [a["text"] for a in pair[0]["candidate_answers"]]
                   != [a["text"] for a in pair[1]["candidate_answers"]]):
            raise ValueError("Expected changed-fact preference reversal missing")
    return generated, cases


def make_inputs(axios: dict, django: dict, tokenizer_bytes: bytes, encode) -> dict:
    if sha_bytes(tokenizer_bytes) != TOKENIZER_SHA256:
        raise ValueError("Official tokenizer bytes do not match pinned SHA256")
    _, cases = load_cases(axios, django)
    records = []
    for case in cases:
        for ans in case["candidate_answers"]:
            task = render(case["question"], ans["text"])
            tokens = encode(task)
            if (not isinstance(tokens, list) or not 8 <= len(tokens) <= 192
                    or tokens[0] != 50281 or tokens[-1] != 50282
                    or any(type(v) is not int or not 0 <= v < 50368 for v in tokens)):
                raise ValueError("Official token framing invalid or over 192-token cap; no truncation")
            records.append({
                "id": case["id"] + "--" + ans["id"],
                "case_id": case["id"],
                "answer_id": ans["id"],
                "question_sha256": sha(case["question"]),
                "answer_sha256": sha(ans["text"]),
                "rendered_sha256": sha(task),
                "token_count": len(tokens), "input_ids": tokens,
                "source_executed_provisional_preference": case["research_source_expected"],
                "independently_human_adjudicated": False,
            })
    if len(records) != 16 or len({r["id"] for r in records}) != 16:
        raise ValueError("Exactly sixteen unique binary scoring inputs required")
    return {
        "schema_version": 1, "status": INPUT_STATUS,
        "intent_family": "SECURITY_REVIEW", "intent": "SECURITY_REVIEW_GENERAL",
        "official_tokenizer_sha256": TOKENIZER_SHA256,
        "source_report_sha256": {"axios": sha_bytes(json.dumps(axios, sort_keys=True, separators=(",", ":")).encode()),
                                 "django": sha_bytes(json.dumps(django, sort_keys=True, separators=(",", ":")).encode())},
        "source_case_count": 18, "selected_case_count": 8,
        "model_score_input_count": 16,
        "known_previously_studied_families": True,
        "blind_holdout": False, "independent_human_labels": 0,
        "source_rules_are_researcher_provisional": True,
        "no_training_or_registration": True,
        "inputs": records,
    }


def audit(actual_inputs: dict, scores: dict, axios: dict, django: dict) -> dict:
    """Audit actual OFFICIAL-SCORE.json outputs against untouched source case identity.

    A green result means we checked real scores, NOT that the model passed.
    """
    _, cases = load_cases(axios, django)
    if (not isinstance(actual_inputs, dict) or actual_inputs.get("status") != INPUT_STATUS
            or actual_inputs.get("schema_version") != 1
            or actual_inputs.get("intent_family") != "SECURITY_REVIEW"
            or actual_inputs.get("intent") != "SECURITY_REVIEW_GENERAL"
            or actual_inputs.get("official_tokenizer_sha256") != TOKENIZER_SHA256
            or actual_inputs.get("source_case_count") != 18
            or actual_inputs.get("selected_case_count") != 8
            or actual_inputs.get("model_score_input_count") != 16
            or actual_inputs.get("known_previously_studied_families") is not True
            or actual_inputs.get("blind_holdout") is not False
            or actual_inputs.get("independent_human_labels") != 0
            or actual_inputs.get("source_rules_are_researcher_provisional") is not True
            or actual_inputs.get("no_training_or_registration") is not True
            or actual_inputs.get("source_report_sha256") != {
                "axios": sha_bytes(json.dumps(axios, sort_keys=True, separators=(",", ":")).encode()),
                "django": sha_bytes(json.dumps(django, sort_keys=True, separators=(",", ":")).encode()),
            }):
        raise ValueError("Source identity or research-only safeguards altered")
    expected = [(case, ans) for case in cases for ans in case["candidate_answers"]]
    rows = actual_inputs.get("inputs")
    if not isinstance(rows, list) or len(rows) != 16:
        raise ValueError("Missing or duplicate official tokenizer records")
    ids = [case["id"] + "--" + ans["id"] for case, ans in expected]
    if set(scores) != set(ids) or len(scores) != 16:
        raise ValueError("Missing/extra/doubled model scores")
    results = {}
    for row, (case, ans), ident in zip(rows, expected, ids):
        if (not isinstance(row, dict) or row.get("id") != ident
                or row.get("case_id") != case["id"] or row.get("answer_id") != ans["id"]
                or row.get("question_sha256") != sha(case["question"])
                or row.get("answer_sha256") != sha(ans["text"])
                or row.get("rendered_sha256") != sha(render(case["question"], ans["text"]))
                or row.get("source_executed_provisional_preference") != case["research_source_expected"]
                or row.get("independently_human_adjudicated") is not False
                or type(row.get("token_count")) is not int
                or not 8 <= row["token_count"] <= 192
                or not isinstance(row.get("input_ids"), list)
                or len(row["input_ids"]) != row["token_count"]
                or row["input_ids"][0] != 50281 or row["input_ids"][-1] != 50282
                or any(type(v) is not int or not 0 <= v < 50368 for v in row["input_ids"])):
            raise ValueError("Source-pinned task identity / official token schema altered")
        results[ident] = _score(scores[ident], ident)["float32_value"]
    predictions = []
    for case in cases:
        a, b = results[case["id"]+"--A"], results[case["id"]+"--B"]
        preferred = "A" if a > b else "B" if b > a else "TIE"
        predictions.append({
            "case_id": case["id"], "family":case["family"],
            "source_executed_provisional_preference": case["research_source_expected"],
            "model_preferred": preferred, "margin_a_minus_b":a-b,
            "matches_provisional": preferred == case["research_source_expected"],
        })
    by_id = {x["case_id"]: x for x in predictions}
    groups = []
    for name, before, after in GROUPS:
        x, y = by_id[before], by_id[after]
        groups.append({"group":name, "source_rule_reverses": True,
                       "model_preference_reverses": x["model_preferred"] != y["model_preferred"]
                       and "TIE" not in {x["model_preferred"], y["model_preferred"]},
                       "both_source_rules_match":x["matches_provisional"] and y["matches_provisional"]})
    return {
        "schema_version":1, "status":STATUS,
        "original_model_sha256": MODEL_SHA, "foundation_sha256": FOUNDATION_SHA,
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "actual_official_foundation_inference":True,
        "real_score_inputs":16, "real_inference_calls_including_repeats":32,
        "frozen_inputs_sha256":sha_bytes(json.dumps(actual_inputs,sort_keys=True,separators=(",", ":")).encode()),
        "prior_known_source_families":2, "counterfactual_groups":groups,
        "case_results":predictions,
        "provisional_matches":sum(r["matches_provisional"] for r in predictions),
        "complete_provisional_reversals":sum(g["both_source_rules_match"] for g in groups),
        "constant_A_baseline_matches":sum(c["research_source_expected"]=="A" for c in cases),
        "constant_B_baseline_matches":sum(c["research_source_expected"]=="B" for c in cases),
        "blind_holdout":False, "independent_expert_labels":0,
        "network_eligible":False, "model_release_veto_remains":True,
        "registered_evaluator":False, "automatic_registration_permitted":False,
        "notice":"Actual model preferences on known source-executed research cases, compared only with researcher-provisional source observation. The result may fail. No expert validation, measured security accuracy, new material submission, or registration is claimed.",
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Record real original-model scores on known Phase3X harder evidence; NEVER register")
    p.add_argument("--axios",type=Path,required=True)
    p.add_argument("--django",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--tokenizer",type=Path)
    p.add_argument("--inputs",type=Path)
    p.add_argument("--scores-dir",type=Path)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ValueError("refuse overwrite existing score evidence")
        ax=json.loads(a.axios.read_text())
        dj=json.loads(a.django.read_text())
        if a.tokenizer is not None and a.inputs is None and a.scores_dir is None:
            from tokenizers import Tokenizer
            raw=a.tokenizer.read_bytes()
            tokenizer=Tokenizer.from_str(raw.decode())
            report=make_inputs(ax,dj,raw,lambda task:tokenizer.encode(task,add_special_tokens=True).ids)
            a.out.parent.mkdir(parents=True,exist_ok=True)
            for row in report["inputs"]:
                dest=a.out.parent/("SCORE-"+row["id"]+".json")
                if dest.exists() or not re.fullmatch(r"[a-z0-9-]+--[AB]",row["id"]):
                    raise ValueError("unsafe score input path or overwrite")
            for row in report["inputs"]:
                (a.out.parent/("SCORE-"+row["id"]+".json")).write_text(json.dumps({"input_ids":row["input_ids"],"attention_mask":[1]*row["token_count"]},separators=(",", ":"))+"\n")
        elif a.inputs is not None and a.scores_dir is not None and a.tokenizer is None:
            frozen=json.loads(a.inputs.read_text())
            scores={}
            for row in frozen["inputs"]:
                ident=row.get("id")
                if not isinstance(ident,str) or not re.fullmatch(r"[a-z0-9-]+--[AB]",ident):
                    raise ValueError("unsafe score output path")
                scores[ident]=json.loads((a.scores_dir/ident/"OFFICIAL-SCORE.json").read_text())
            report=audit(frozen,scores,ax,dj)
        else:
            raise ValueError("use either --tokenizer or --inputs AND --scores-dir")
        a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        print(json.dumps({k:v for k,v in report.items() if k in {"status","real_score_inputs","provisional_matches","complete_provisional_reversals","blind_holdout","automatic_registration_permitted"}},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ScoreProofError,IndexError) as e:
        p.exit(1,f"FALSUM PHASE3Y REAL SCORE ERROR: {e}\n")


if __name__ == "__main__":
    raise SystemExit(main())