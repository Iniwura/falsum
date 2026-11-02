"""Phase 3J: audit actual full Foundation+LoRA scores on two *known* families.

The observed model may fail. Negative results must pass collection/verification.
This diagnostic never replaces the Phase 3D release veto or human approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase3j_inputs import FAMILIES, STATUS as INPUT_STATUS, MAX_TOKENS, proof, render, sha
from .phase3c_score_inputs import TOKENIZER_SHA256
from .phase3c_score_report import _score, ScoreProofError, MODEL_SHA, FOUNDATION_SHA

STATUS = "PHASE3J_ACTUAL_FOUNDATION_TWO_KNOWN_FAMILY_MARGINS_DIAGNOSTIC_ONLY"


def analyze(inputs: dict, actual_scores: dict, root: Path) -> dict:
    if (not isinstance(inputs, dict) or inputs.get("schema_version") != 1
            or inputs.get("status") != INPUT_STATUS
            or inputs.get("source_provenance") != proof(root)
            or inputs.get("official_tokenizer_sha256") != TOKENIZER_SHA256
            or inputs.get("model_family_count") != 2 or inputs.get("context_count") != 4
            or inputs.get("score_input_count") != 8
            or inputs.get("frozen_known_historical_families") is not True
            or inputs.get("unseen_blind_holdout") is not False
            or inputs.get("training_material_generated") is not False
            or inputs.get("independent_expert_labels") != 0
            or inputs.get("eligible_anjoman_rows") != 0
            or inputs.get("network_eligible") is not False
            or inputs.get("existing_model_release_veto_still_applies") is not True
            or not isinstance(inputs.get("inputs"), list)
            or len(inputs["inputs"]) != 8):
        raise ScoreProofError("not exact source-anchored research-only model inputs")
    expected = [(f, c, a) for f in FAMILIES for c in f["contexts"] for a in f["answers"]]
    ids = [f["id"] + "--" + c[0] + "--" + a[0] for f,c,a in expected]
    if ([r.get("id") if isinstance(r, dict) else None for r in inputs["inputs"]] != ids
            or not isinstance(actual_scores, dict) or set(actual_scores) != set(ids)):
        raise ScoreProofError("duplicate, missing or unexpected model score identities")
    observed = {}
    scores = []
    for row, (f, c, a), key in zip(inputs["inputs"], expected, ids):
        if (row.get("family") != f["id"] or row.get("context") != c[0]
                or row.get("answer_id") != a[0] or row.get("task_sha256") != sha(c[1])
                or row.get("answer_sha256") != sha(a[1])
                or row.get("rendered_sha256") != sha(render(f,c,a))
                or row.get("provisional_runtime_rule_preferred") != c[2]
                or row.get("human_expert_approved") is not False
                or type(row.get("token_count")) is not int
                or not 8 <= row["token_count"] <= MAX_TOKENS
                or not isinstance(row.get("input_ids"),list)
                or len(row["input_ids"]) != row["token_count"]
                or row["input_ids"][0] != 50281 or row["input_ids"][-1] != 50282
                or any(type(v) is not int or v < 0 or v >= 50368 for v in row["input_ids"])):
            raise ScoreProofError("rewritten question, answer, tokenizer framing or provisional context identity")
        verified = _score(actual_scores[key], key)
        observed[key] = verified["float32_value"]
        scores.append({"input_id":key,"score_hex":verified["float32_score_hex"],
                       "model_loaded":True,"repeat_bits_consistent":True})
    families = []
    for f in FAMILIES:
        contexts=[]
        for c in f["contexts"]:
            first, second = f["answers"]
            name1=f["id"] + "--" + c[0] + "--" + first[0]
            name2=f["id"] + "--" + c[0] + "--" + second[0]
            margin=observed[name1]-observed[name2]
            preferred=first[0] if margin>0 else second[0] if margin<0 else "TIE"
            contexts.append({
                "context":c[0],"margin_answer_1_minus_answer_2":margin,
                "model_preferred":preferred,"provisional_runtime_rule_preferred":c[2],
                "matches_provisional_runtime_rule":preferred==c[2]
            })
        families.append({
            "family":f["id"],"contexts":contexts,
            "reversed_preference_on_changed_runtime_fact":(
                contexts[0]["model_preferred"] != contexts[1]["model_preferred"]
                and "TIE" not in {x["model_preferred"] for x in contexts}
            ),
            "both_contexts_match_provisional_runtime_rule":all(x["matches_provisional_runtime_rule"] for x in contexts),
            "independent_expert_certified":False,
        })
    return {
        "schema_version":1,"status":STATUS,
        "real_official_foundation_loaded":True,
        "model_sha256":MODEL_SHA,"foundation_sha256":FOUNDATION_SHA,
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "source_provenance":inputs["source_provenance"],
        "real_model_score_inputs":8,"real_inference_calls_including_repeats":16,
        "score_packets":scores,"context_families":families,
        "contexts_matching_provisional_rules":sum(r["matches_provisional_runtime_rule"] for f in families for r in f["contexts"]),
        "families_with_ranking_reversal":sum(f["reversed_preference_on_changed_runtime_fact"] for f in families),
        "families_matching_both_provisional_rules":sum(f["both_contexts_match_provisional_runtime_rule"] for f in families),
        "blind_independent_holdout":False,"expert_approved_labels":0,
        "eligible_anjoman_rows":0,"new_training_pairs":0,
        "new_model_trained":False,"model_release_veto_remains":True,
        "automatic_registration_permitted":False,
        "registered_evaluator":False,"network_eligible":False,
        "next_action":"DO_NOT_REGISTER_UNTIL_INDEPENDENTLY_ADJUDICATED_PROJECT_DISJOINT_VALIDATION",
        "notice":"Actual scores for the original AI-provisional LoRA on known historical runtime-backed comparisons. This is diagnostic, not independently validated or blind accuracy. The original 0/2 Phase 3D model quality veto remains in force even if scores improve here."
    }


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Audit real official Foundation context-sensitive score packets without releasing the LoRA")
    p.add_argument("--inputs",required=True,type=Path)
    p.add_argument("--scores-dir",required=True,type=Path)
    p.add_argument("--root",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ScoreProofError("refuse overwrite prior model assessment")
        inputs=json.loads(a.inputs.read_text())
        actual={}
        for row in inputs["inputs"]:
            id_=row["id"]
            if not isinstance(id_,str) or id_.count("--")!=2 or not id_.replace("-","").isalnum():
                raise ScoreProofError("untrusted input path")
            actual[id_]=json.loads((a.scores_dir/id_/"OFFICIAL-SCORE.json").read_text())
        report=analyze(inputs,actual,a.root)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps({
            "status":STATUS,
            "context_rule_matches":report["contexts_matching_provisional_rules"],
            "complete_families_matching_both":report["families_matching_both_provisional_rules"],
            "ranking_reversals":report["families_with_ranking_reversal"],
            "blind_heldout_accuracy_certified":False,
            "automatic_registration_permitted":False,
        },indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ScoreProofError) as exc:
        p.exit(1,f"FALSUM PHASE3J REAL MODEL AUDIT ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
