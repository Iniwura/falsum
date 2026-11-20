"""Public source-context challenge for *actual third-party supplied* predictions.

This tiny, openly authored, publicly solved diagnostic is usable without the
now-unavailable historical LoRA artifact. Its three cases are NOT a blind
holdout, statistical model accuracy or independent expert gold. No candidate
model is ever called by this module. Predictions are external/unverified until
a separately authenticated origin exists; local baselines stay synthetic.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path

from .phase5m_real_source_sensitive_model import (
    ROOT, CONDITIONS, ANSWERS, questions, protocol, sha, canonical_json,
    DiagnosticError, read_json, require,
)
from .phase5l_pymdown_upstream_replay import load_lock as load_source_lock

STATUS_CHALLENGE="PHASE5M_PUBLIC_SOURCE_CONTEXT_EXPLICIT_CODE_EVIDENCE_NOT_BLIND_GOLD"
STATUS_TEMPLATE="PHASE5M_UNVERIFIED_CANDIDATE_DECISIONS_UNFILLED"
STATUS_RESULT="PHASE5M_PUBLIC_SOURCE_CONTEXT_DIAGNOSTIC_NO_STATISTICAL_ACCURACY"
ALLOWED=("A","B","ABSTAIN")
EXPECTED={"code-context-a":"A","code-context-b":"B","source-omitted":"ABSTAIN"}
BASELINES={"always-A":"A","always-B":"B","always-ABSTAIN":"ABSTAIN"}


def _id(condition:str)->str:
    require(condition in CONDITIONS,"invalid source task condition")
    return hashlib.sha256(
        ("falsum/open-public/phase5m/source-condition/"+condition).encode()
    ).hexdigest()[:32]


def construct(root:Path=ROOT)->tuple[dict,dict[str,str],dict[str,str]]:
    p=protocol(root)
    lock=load_source_lock(root)
    require(lock["original_fix_commit"]==p["source_fix_commit"]
            and lock["direct_vulnerable_parent"]==p["source_parent_commit"]
            and lock["original_parent_source_blob_sha1"]==p["source_blob_parent"]
            and lock["original_fixed_source_blob_sha1"]==p["source_blob_fixed"],
            "source-test repair evidence identity drift")
    qs=questions(p)
    texts={v["id"]:v["text"] for v in p["candidate_answers"]}
    rows=[]
    protected_expected={}
    source_condition={}
    for condition in CONDITIONS:
        ident=_id(condition)
        protected_expected[ident]=EXPECTED[condition]
        source_condition[ident]=condition
        commit=(p["source_parent_commit"] if condition=="code-context-a"
                else p["source_fix_commit"] if condition=="code-context-b" else None)
        rows.append({
            "id":ident,
            "question":qs[condition],
            "answer_options":[{"choice":label,"text":texts[label]} for label in ANSWERS],
            "response_choices":list(ALLOWED),
            # Git source evidence is public and fully open-book; only
            # revision ROLE labels and hidden per-row truth are omitted.
            "source_git_sha":commit,
            "source_code_url":(
                "https://github.com/"+p["source_project"]+"/blob/"+commit+"/pymdownx/snippets.py"
                if commit is not None else None
            ),
        })
    rows.sort(key=lambda r:r["id"])
    require(len(rows)==3 and len({r["id"] for r in rows})==3
            and Counter(protected_expected.values())=={
                "A":1,"B":1,"ABSTAIN":1,
            },"expected three distinct balanced source facts")
    return ({
        "schema_version":1,
        "status":STATUS_CHALLENGE,
        "intent":"SECURITY_REVIEW_GENERAL",
        "source_replay_evidence_run":"https://github.com/Iniwura/falsum/actions/runs/"
            +str(p["verified_real_source_test_run"]),
        "frozen_before_scoring_protocol_sha256":sha(
            (root/"data/phase5m-preinference-original-lora-pymdown-source-sensitivity.json").read_bytes()
        ),
        "public_questions":3,
        "distinct_upstream_projects":1,
        "source_revision_conditions":2,
        "source_omitted_controls":1,
        "answer_key_excluded":True,
        "not_model_or_pretraining_blind":True,
        "independent_appsec_expert_gold_labels":0,
        "actual_model_scores_included":False,
        "trained_improvement_proven":False,
        "official_evaluator_registered":False,
        "official_h2_entry_submitted":False,
        "limitations":"Three public researcher-constructed diagnostic questions using one authentic "
            "upstream parent/fix pair. The source-omitted control SHOULD ABSTAIN but "
            "is author-defined evidence-limited calibration, not human gold. Answers "
            "are recoverable from public source and generator. No statistical generalization, "
            "independent human adjudication, network ranking or live model inference.",
        "questions":rows,
    },protected_expected,source_condition)


def template(challenge:dict)->dict:
    return {
        "schema_version":1,
        "status":STATUS_TEMPLATE,
        "challenge_sha256":sha(canonical_json(challenge)),
        "decisions":[{"id":x["id"],"choice":None,"reason":None}
                     for x in challenge["questions"]],
    }


def validate(challenge:dict,submitted:dict)->dict[str,str]:
    require(isinstance(submitted,dict) and set(submitted)=={
        "schema_version","status","challenge_sha256","decisions"
    } and type(submitted["schema_version"]) is int
            and submitted["schema_version"]==1
            and submitted["status"]==STATUS_TEMPLATE
            and submitted["challenge_sha256"]==sha(canonical_json(challenge)),
            "model candidate did not submit the exact challenge")
    rows=submitted["decisions"]
    need=[x["id"] for x in challenge["questions"]]
    require(isinstance(rows,list) and len(rows)==3,"exactly three source decisions required")
    result={}
    for row,expected_id in zip(rows,need):
        require(isinstance(row,dict) and set(row)=={"id","choice","reason"}
                and row["id"]==expected_id and row["choice"] in ALLOWED
                and (row["reason"] is None or
                     (isinstance(row["reason"],str) and len(row["reason"])<=1200)),
                "unknown, reordered, invalid or unfilled candidate decision")
        result[expected_id]=row["choice"]
    require(len(result)==3,"duplicate candidate question identity")
    return result


def score(challenge:dict,truth:dict[str,str],source_conditions:dict[str,str],
          choices:dict[str,str],*,origin:str)->dict:
    require(origin in ("SYNTHETIC_DISCLOSED_BASELINE","EXTERNAL_UNVERIFIED_PREDICTIONS"),
            "unverified candidates cannot claim independent AppSec verification")
    require(len(truth)==len(source_conditions)==len(choices)==3
            and set(truth)==set(source_conditions)==set(choices)
            and Counter(truth.values())=={"A":1,"B":1,"ABSTAIN":1}
            and all(choices[k] in ALLOWED for k in choices),
            "source answer key or candidate decisions changed")
    matrix={label:{choice:0 for choice in ALLOWED} for label in ALLOWED}
    for key in truth:
        matrix[truth[key]][choices[key]]+=1
    correct=sum(choices[k]==truth[k] for k in truth)
    by_source={source_conditions[k]:choices[k] for k in truth}
    expected_pair=by_source["code-context-a"]=="A" and by_source["code-context-b"]=="B"
    return {
        "schema_version":1,"status":STATUS_RESULT,
        "intent":"SECURITY_REVIEW_GENERAL",
        "candidate_origin":origin,
        "challenge_sha256":sha(canonical_json(challenge)),
        "source_replay_evidence_run":challenge["source_replay_evidence_run"],
        "questions_scored":3,
        "source_condition_facts":2,
        "source_omitted_controls":1,
        "reference_distribution":{"A":1,"B":1,"ABSTAIN":1},
        "confusion_true_rows_predicted_columns":matrix,
        "total_exact_source_derived_matches":correct,
        "source_fact_matches_out_of_two":int(by_source["code-context-a"]=="A")
            +int(by_source["code-context-b"]=="B"),
        "source_sensitive_complete_correct_reversal":expected_pair,
        "source_context_choice_changed":(
            by_source["code-context-a"]!=by_source["code-context-b"]
            and by_source["code-context-a"]!="ABSTAIN"
            and by_source["code-context-b"]!="ABSTAIN"
        ),
        "no_source_control_abstained":by_source["source-omitted"]=="ABSTAIN",
        "source_omitted_choice":by_source["source-omitted"],
        "raw_match_fraction":round(correct/3,6),
        "macro_class_recall":round(sum(matrix[x][x] for x in ALLOWED)/3,6),
        "independent_human_expert_gold_labels":0,
        "public_author_generated_reference_not_expert_gold":True,
        "statistically_valid_model_accuracy_estimate":False,
        "model_inference_performed_by_this_scorer":False,
        "registered_telegraph_evaluator":False,
        "actual_trained_model_improvement":False,
        "official_h2_entry_submitted":False,
        "limitation":challenge["limitations"],
    }


def baseline(challenge:dict,choice:str)->dict[str,str]:
    require(choice in BASELINES,"unknown declared constant-choice baseline")
    return {q["id"]:BASELINES[choice] for q in challenge["questions"]}


def write_new(path:Path,obj:dict)->None:
    require(not path.exists() and not path.is_symlink(),
            "refuse to overwrite source-challenge evidence or responses")
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(obj,f,sort_keys=True,indent=2)
        f.write("\n")


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Score actual candidate security-review judgments on one source-sensitive parent/fix pair; NOT a model")
    sub=parser.add_subparsers(dest="mode",required=True)
    exp=sub.add_parser("export")
    exp.add_argument("--questions-out",type=Path,required=True)
    exp.add_argument("--template-out",type=Path,required=True)
    bas=sub.add_parser("baseline")
    bas.add_argument("--strategy",required=True,choices=tuple(BASELINES))
    bas.add_argument("--out",type=Path,required=True)
    sc=sub.add_parser("score")
    sc.add_argument("--predictions",type=Path,required=True)
    sc.add_argument("--out",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        challenge,truth,conditions=construct()
        if args.mode=="export":
            require(args.questions_out.resolve()!=args.template_out.resolve()
                    and not any(p.exists() or p.is_symlink() for p in (
                        args.questions_out,args.template_out
                    )),"both source question and empty candidate paths must be new")
            write_new(args.questions_out,challenge)
            write_new(args.template_out,template(challenge))
            print(json.dumps({"public_questions":3,"source_facts":2,
                              "abstain_control":1,"model_inference":False},sort_keys=True))
        elif args.mode=="baseline":
            result=score(challenge,truth,conditions,
                         baseline(challenge,args.strategy),origin="SYNTHETIC_DISCLOSED_BASELINE")
            result["baseline"]=args.strategy
            write_new(args.out,result)
            print(json.dumps({"strategy":args.strategy,"exact_matches":result[
                "total_exact_source_derived_matches"],"not_model_accuracy":True},sort_keys=True))
        else:
            require(args.predictions.resolve()!=args.out.resolve(),
                    "cannot overwrite candidate evidence")
            raw=args.predictions.read_bytes()
            require(0<len(raw)<10000,"missing or oversized candidate source judgments")
            choices=validate(challenge,read_json(raw))
            result=score(challenge,truth,conditions,choices,
                         origin="EXTERNAL_UNVERIFIED_PREDICTIONS")
            write_new(args.out,result)
            print(json.dumps({"exact":result["total_exact_source_derived_matches"],
                              "paired_reversal":result["source_sensitive_complete_correct_reversal"],
                              "not_independent_gold":True},sort_keys=True))
        return 0
    except (OSError,ValueError,KeyError,TypeError,DiagnosticError) as exc:
        parser.exit(1,"FALSUM PHASE5M PUBLIC SOURCE CONTEXT SCORER BLOCKED: "
                    +str(exc)[:230]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
