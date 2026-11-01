"""Evaluate ACTUAL official loaded Foundation scores on paired contexts.

Never require results to be positive: measured failures must be archived.
Answers remain identical within each version/flag family. A model's alignment
with AI-provisional rule expectations is NOT independently validated accuracy.
"""
from __future__ import annotations
import argparse
import json
import hashlib
from pathlib import Path

from .phase3c_score_report import _score, ScoreProofError
from .phase3d_counterfactual_inputs import STATUS as INPUT_STATUS,FAMILIES
from .phase3c_score_inputs import TOKENIZER_SHA256

STATUS="PHASE3D_REAL_FOUNDATION_COUNTERFACTUAL_REVERSAL_DIAGNOSTIC_NOT_CERTIFIED"


def compare(inputs:dict,actuals:dict)->dict:
    if (not isinstance(inputs,dict) or inputs.get("status")!=INPUT_STATUS
        or inputs.get("research_only") is not True
        or inputs.get("network_eligible") is not False
        or inputs.get("independent_expert_labels")!=0
        or inputs.get("official_tokenizer_sha256")!=TOKENIZER_SHA256
        or inputs.get("actual_node_token_cap")!=512
        or inputs.get("bounded_counterfactual_token_cap")!=192
        or inputs.get("candidate_answer_bytes_fixed_within_each_family") is not True
        or inputs.get("context_counterfactual_families")!=2
        or inputs.get("unseen_or_blind_holdout") is not False
        or not isinstance(inputs.get("inputs"),list) or len(inputs["inputs"])!=8):
        raise ScoreProofError("unapproved or incomplete research experiment")
    expected_ids=[f["family"]+"--"+c[0]+"--"+a[0]
                  for f in FAMILIES for c in f["contexts"] for a in f["fixed_answers"]]
    if [r.get("id") for r in inputs["inputs"]]!=expected_ids:
        raise ScoreProofError("model input identity or ordering changed")
    if not isinstance(actuals,dict) or set(actuals)!=set(expected_ids):
        raise ScoreProofError("missing, duplicate or unexpected real model score results")
    checks=[]
    values={}
    for r in inputs["inputs"]:
        id_=r["id"]
        expected_f,expected_c,expected_a=id_.split("--")
        if (r.get("family")!=expected_f or r.get("context")!=expected_c
            or r.get("answer_id")!=expected_a or r.get("approved_expert_label") is not False
            or type(r.get("token_count")) is not int
            or not 8<=r["token_count"]<=192
            or not isinstance(r.get("input_ids"),list)
            or len(r["input_ids"])!=r["token_count"]
            or r["input_ids"][0]!=50281 or r["input_ids"][-1]!=50282
            or any(type(v) is not int or v<0 or v>=50368 for v in r["input_ids"])):
            raise ScoreProofError("provisional input count/identity invalid")
        f=next(f for f in FAMILIES if f["family"]==expected_f)
        c=next(c for c in f["contexts"] if c[0]==expected_c)
        answer=next(answer for answer in f["fixed_answers"] if answer[0]==expected_a)
        task=c[1]
        rendered="### Task:\n"+task+"\n\n### Answer:\n"+answer[1]
        if (r.get("task_sha256")!=hashlib.sha256(task.encode()).hexdigest()
            or r.get("answer_sha256")!=hashlib.sha256(answer[1].encode()).hexdigest()
            or r.get("rendered_input_sha256")!=hashlib.sha256(rendered.encode()).hexdigest()
            or r.get("provisional_rule_based_preferred_answer")!=c[2]):
            raise ScoreProofError("the task, answer or provisional labels were rewritten")
        scored=_score(actuals[id_],id_)
        values[id_]=scored
        checks.append({"input_id":id_,"official_score_hex":scored["float32_score_hex"],
                       "official_score_f32":scored["float32_value"],
                       "actual_foundation_loaded":True,
                       "exact_repeated_score_bits":True})
    families=[]
    for f in FAMILIES:
        pair=[]
        for context_id,_,expect in f["contexts"]:
            a_id=f["family"]+"--"+context_id+"--"+f["fixed_answers"][0][0]
            b_id=f["family"]+"--"+context_id+"--"+f["fixed_answers"][1][0]
            margin=values[a_id]["float32_value"]-values[b_id]["float32_value"]
            preferred=(f["fixed_answers"][0][0] if margin>0 else
                       f["fixed_answers"][1][0] if margin<0 else "TIE_NO_PREFERENCE")
            pair.append({"context":context_id,
                         "answer_a":f["fixed_answers"][0][0],
                         "answer_b":f["fixed_answers"][1][0],
                         "margin_a_minus_b":margin,
                         "model_preferred":preferred,
                         "rule_provisional_expected":expect,
                         "diagnostic_matches_provisional_rule":preferred==expect})
        families.append({
            "family":f["family"],"contexts":pair,
            "both_context_preferences_match_provisional_rule":all(x["diagnostic_matches_provisional_rule"] for x in pair),
            "ranking_reverses_when_one_deployment_fact_changes":(
                pair[0]["model_preferred"]!=pair[1]["model_preferred"]
                and "TIE_NO_PREFERENCE" not in (pair[0]["model_preferred"],pair[1]["model_preferred"])),
            "expert_certified":False
        })
    return {
        "schema_version":1,"status":STATUS,"actual_official_foundation_loaded":True,
        "model_package_original_and_sha_verified":True,
        "real_independent_score_inputs":8,
        "real_inference_calls_including_repeats":16,
        "repeat_float32_bits_identical":True,
        "scores":checks,"counterfactual_families":families,
        "families_with_preference_reversal":sum(x["ranking_reverses_when_one_deployment_fact_changes"] for x in families),
        "families_matching_both_provisional_expected_preferences":sum(x["both_context_preferences_match_provisional_rule"] for x in families),
        "families_tested":2,"rule_derived_not_independent_accuracy":True,
        "labels_human_adjudicated":0,
        "verified_real_application_exploits":0,"accepted_anjoman_rows":0,
        "network_eligible":False,"registered_evaluator":False,
        "notice":"Real scores and any failures are preserved unchanged; this is a deliberately small, researcher-authored counterfactual diagnostic, not a blinded sample or network evaluation."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Report observed genuine Foundation counterfactual margins without fabricating labels")
    p.add_argument("--inputs",type=Path,required=True)
    p.add_argument("--scores-dir",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ScoreProofError("refuse to overwrite score evidence")
        inputs=json.loads(a.inputs.read_text())
        out={}
        for r in inputs["inputs"]:
            src=a.scores_dir/r["id"]/"OFFICIAL-SCORE.json"
            out[r["id"]]=json.loads(src.read_text())
        report=compare(inputs,out)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps({
            "real_inferences":16,
            "families_with_preference_reversal":report["families_with_preference_reversal"],
            "families_matching_both_provisional_expected_preferences":report["families_matching_both_provisional_expected_preferences"],
            "model_accuracy_certified":False,"network_eligible":False
        },indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ScoreProofError,StopIteration) as exc:
        p.exit(1,f"FALSUM REAL COUNTERFACTUAL DIAGNOSTIC ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
