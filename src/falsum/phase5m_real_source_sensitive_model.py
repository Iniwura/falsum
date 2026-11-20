"""Phase 5M: original unchanged (FAILED) Foundation LoRA, new verified source pair.

Actual public upstream Git code is re-checked at its immutable original commits.
All question text, answer text, source fact expectations and the original model
package were frozen in a prior Git commit BEFORE running any new inference.

No registered new evaluator, no trained gain, no human AppSec gold, not a
model-pretraining blind holdout. The source-omitted arm has NO correct answer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from .phase3c_score_inputs import TOKENIZER_SHA256
from .phase3c_score_report import _score, ScoreProofError, MODEL_SHA, FOUNDATION_SHA
from .phase5l_pymdown_upstream_replay import git_blob, load_lock as load_source_lock

ROOT=Path(__file__).resolve().parents[2]
PROTOCOL_PATH="data/phase5m-preinference-original-lora-pymdown-source-sensitivity.json"
PROTOCOL_GIT_BLOB_SHA="b50c6e1ad386f4bbf2faa7dd15ddba35b860f9b3"
STATUS_INPUT="PHASE5M_REAL_MODEL_SIX_PRE_FROZEN_SOURCE_CONTEXT_INPUTS_NOT_GOLD"
STATUS_RESULT="PHASE5M_REAL_UNCHANGED_ORIGINAL_LORA_PYMDOWN_SOURCE_SENSITIVITY_NOT_ACCURACY"
CONDITIONS=("code-context-a","code-context-b","source-omitted")
ANSWERS=("A","B")
TOKEN_CAP=256
SHA40=re.compile(r"^[a-f0-9]{40}$")
SAFE_ID=re.compile(r"^(?:code-context-[ab]|source-omitted)--[AB]$")
ALL_KEYS=tuple(f"{c}--{a}" for c in CONDITIONS for a in ANSWERS)


class DiagnosticError(ValueError):
    pass


def require(flag: bool, msg: str) -> None:
    if not flag:
        raise DiagnosticError(msg)


def sha(raw:bytes)->str:
    return hashlib.sha256(raw).hexdigest()


def sha_text(s:str)->str:
    return sha(s.encode("utf-8"))


def canonical_json(value:dict)->bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_json(raw:bytes)->dict:
    def strict_pairs(pairs):
        out={}
        for k,v in pairs:
            require(k not in out,"duplicate JSON key: "+k)
            out[k]=v
        return out
    try:
        obj=json.loads(raw, object_pairs_hook=strict_pairs)
    except (UnicodeError, ValueError) as exc:
        raise DiagnosticError("corrupt diagnostic JSON") from exc
    require(isinstance(obj,dict),"expected a JSON object")
    return obj


def protocol(root:Path=ROOT)->dict:
    raw=(root/PROTOCOL_PATH).read_bytes()
    require(0<len(raw)<12000 and git_blob(raw)==PROTOCOL_GIT_BLOB_SHA,
            "pre-inference task/model protocol has changed")
    p=read_json(raw)
    require(p.get("schema_version")==1 and type(p["schema_version"]) is int
            and p.get("status")=="PHASE5M_PRE_INFERENCE_FROZEN_SOURCE_SENSITIVITY_PROTOCOL_RESEARCH_ONLY"
            and p.get("intent")=="SECURITY_REVIEW_GENERAL"
            and p.get("source_project")=="facelessuser/pymdown-extensions"
            and p.get("source_fix_commit")=="63b7835776d703d6c339cf2110d9888f676efc0c"
            and p.get("source_parent_commit")=="3d185501daaa1424c4a8d42124112c44ef6ab635"
            and p.get("source_blob_parent")=="305c7c0aae68516f4aad77c2430234762e981688"
            and p.get("source_blob_fixed")=="b808d7b929fec0962c4b41ca0a70ed4e696d0fc5"
            and p.get("source_selection_lock_git_blob_sha1")=="79e27d78376dde9cdd9d4e628a95cc3cc7ae63ee"
            and p.get("verified_real_source_test_run")==44716279199
            and p.get("original_model_sha256")==MODEL_SHA
            and p.get("official_foundation_sha256")==FOUNDATION_SHA
            and p.get("official_tokenizer_sha256")==TOKENIZER_SHA256
            and p.get("original_model_artifact_run")==41304788714
            and p.get("original_score_inputs")==6
            and p.get("real_inference_repeats_per_input")==2
            and p.get("source_sensitive_pair_count")==1
            and [x["id"] for x in p.get("test_conditions",[])]==list(CONDITIONS)
            and [x["id"] for x in p.get("candidate_answers",[])]==list(ANSWERS)
            and p.get("declared_source_fact_reference_labels")=={
                "code-context-a":"A","code-context-b":"B","source-omitted":None
            }
            and p.get("fixed_model_before_selection") is True
            and p.get("no_training_or_prompt_tuning_after_observing_scores") is True
            and p.get("public_pretraining_disjoint") is False
            and p.get("independent_human_expert_gold_labels")==0
            and p.get("new_anjoman_eligible_rows")==0
            and p.get("network_model_registered") is False
            and p.get("official_H2_entry_submitted") is False,
            "pre-inference frozen source, model or no-gold protocol changed")
    require(all(isinstance(x["text"],str) and len(x["text"])>75
                for x in p["candidate_answers"]), "missing frozen answer content")
    require(all(isinstance(p[k],str) and len(p[k])>70 for k in
                ("question_prefix","context_template","no_source_context")),
            "source question or neutral control missing")
    require(p["test_conditions"][0]["code_revision"]=="parent"
            and p["test_conditions"][1]["code_revision"]=="fixed"
            and p["test_conditions"][2]["code_revision"] is None
            and p["test_conditions"][2]["expected_source_fact"] is None
            and p["test_conditions"][0]["expected_source_fact"]=="A"
            and p["test_conditions"][1]["expected_source_fact"]=="B",
            "paired source revision expectations missing")
    return p


def git(worktree:Path,*args:str)->bytes:
    cp=subprocess.run(["git","-C",str(worktree),*args],capture_output=True,timeout=30,check=False)
    require(cp.returncode==0, "original upstream Git source checkout unavailable")
    return cp.stdout


def verify_source(worktree:Path,p:dict)->dict[str,str]:
    require(worktree.is_dir() and not worktree.is_symlink(),
            "missing real original upstream Git worktree")
    require(git(worktree,"rev-parse","HEAD").decode().strip()==p["source_fix_commit"],
            "upstream worktree is not original pinned fixed SHA")
    require(git(worktree,"show","-s","--format=%P","HEAD").decode().strip()==
            p["source_parent_commit"],"original fixed source's direct parent does not match")
    source_path="pymdownx/snippets.py"
    blobs={}
    for name,rev,expected_blob,expected_guard in (
        ("parent",p["source_parent_commit"],p["source_blob_parent"],
         p["original_source_guard_parent"]),
        ("fixed",p["source_fix_commit"],p["source_blob_fixed"],
         p["original_source_guard_fixed"]),
    ):
        raw=git(worktree,"show",rev+":"+source_path)
        require(git_blob(raw)==expected_blob,"original Git source blob SHA no longer authentic: "+name)
        decoded=raw.decode("utf-8")
        require(expected_guard in decoded,
                "precommitted original source guard no longer matches actual source: "+name)
        blobs[name]=decoded
    return blobs


def questions(p:dict)->dict[str,str]:
    result={}
    for condition in CONDITIONS:
        if condition=="code-context-a":
            context=p["context_template"].replace("{guard}",p["original_source_guard_parent"])
        elif condition=="code-context-b":
            context=p["context_template"].replace("{guard}",p["original_source_guard_fixed"])
        else:
            context=p["no_source_context"]
        text=p["question_prefix"]+"\n\n"+context
        # Avoid silently leaking the author's answer in a revision label or version tag.
        require("parent" not in text.casefold() and "fixed" not in text.casefold()
                and "vulnerable" not in text.casefold() and "patched" not in text.casefold(),
                "benchmark prompt accidentally exposes source role")
        result[condition]=text
    require(len(result)==3 and result["code-context-a"]!=result["code-context-b"]
            and result["source-omitted"] not in (
                result["code-context-a"],result["code-context-b"]),
            "duplicate or missing source/context inputs")
    return result


def make_inputs(p:dict,tokenizer_raw:bytes,encode)->dict:
    require(sha(tokenizer_raw)==TOKENIZER_SHA256,
            "official Foundation tokenizer bytes changed")
    qs=questions(p)
    items=[]
    for condition in CONDITIONS:
        for answer in p["candidate_answers"]:
            ident=f"{condition}--{answer['id']}"
            require(SAFE_ID.fullmatch(ident) is not None, "unsafe source scoring packet path")
            rendered="### Task:\n"+qs[condition]+"\n\n### Answer:\n"+answer["text"]
            token_ids=encode(rendered)
            require(isinstance(token_ids,list) and 12<=len(token_ids)<=TOKEN_CAP
                    and token_ids[0]==50281 and token_ids[-1]==50282
                    and all(type(i) is int and 0<=i<50368 for i in token_ids),
                    "real tokenizer framing wrong or token budget >256; refuse truncation")
            items.append({
                "id":ident,"condition":condition,
                "answer_id":answer["id"],
                "question_sha256":sha_text(qs[condition]),
                "answer_sha256":sha_text(answer["text"]),
                "rendered_input_sha256":sha_text(rendered),
                "token_count":len(token_ids),"input_ids":token_ids,
                "source_commit":p["source_parent_commit"] if condition=="code-context-a"
                else p["source_fix_commit"] if condition=="code-context-b" else None,
                "reference_is_independent_expert_gold":False,
            })
    require(len(items)==6 and tuple(x["id"] for x in items)==ALL_KEYS
            and len({tuple(x["input_ids"]) for x in items})==6,
            "six distinct real model-score inputs required")
    return {
        "schema_version":1,"status":STATUS_INPUT,
        "protocol_lock_git_blob":PROTOCOL_GIT_BLOB_SHA,
        "intent":"SECURITY_REVIEW_GENERAL",
        "official_scoring_family":"SECURITY_REVIEW",
        "original_quarantined_model_sha256":MODEL_SHA,
        "official_foundation_sha256":FOUNDATION_SHA,
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "verified_upstream_original_replay_run":p["verified_real_source_test_run"],
        "original_source_facts_rechecked":True,
        "source_sensitive_revisions":2,"no_source_controls":1,
        "model_score_inputs":6,"expected_real_inference_repeats_per_input":2,
        "inputs":items,
        "not_independent_human_gold":True,
        "not_blind_model_pretraining_holdout":True,
        "model_training_or_registration":False,
    }


def validate_inputs(inputs:dict,p:dict)->list[dict]:
    require(isinstance(inputs,dict)
            and set(inputs)=={
                "schema_version","status","protocol_lock_git_blob","intent",
                "official_scoring_family","original_quarantined_model_sha256",
                "official_foundation_sha256","official_tokenizer_sha256",
                "verified_upstream_original_replay_run",
                "original_source_facts_rechecked","source_sensitive_revisions",
                "no_source_controls","model_score_inputs",
                "expected_real_inference_repeats_per_input","inputs",
                "not_independent_human_gold","not_blind_model_pretraining_holdout",
                "model_training_or_registration"
            }
            and type(inputs["schema_version"]) is int
            and inputs["schema_version"]==1
            and inputs["status"]==STATUS_INPUT
            and inputs["protocol_lock_git_blob"]==PROTOCOL_GIT_BLOB_SHA
            and inputs["intent"]=="SECURITY_REVIEW_GENERAL"
            and inputs["official_scoring_family"]=="SECURITY_REVIEW"
            and inputs["original_quarantined_model_sha256"]==MODEL_SHA
            and inputs["official_foundation_sha256"]==FOUNDATION_SHA
            and inputs["official_tokenizer_sha256"]==TOKENIZER_SHA256
            and inputs["verified_upstream_original_replay_run"]==
                p["verified_real_source_test_run"]
            and inputs["original_source_facts_rechecked"] is True
            and inputs["source_sensitive_revisions"]==2
            and inputs["no_source_controls"]==1
            and inputs["model_score_inputs"]==6
            and inputs["expected_real_inference_repeats_per_input"]==2
            and inputs["not_independent_human_gold"] is True
            and inputs["not_blind_model_pretraining_holdout"] is True
            and inputs["model_training_or_registration"] is False,
            "forged or inconsistent source/model input manifest")
    rows=inputs["inputs"]
    require(isinstance(rows,list) and len(rows)==6,
            "six exact original model inputs required")
    qs=questions(p)
    ans={x["id"]:x["text"] for x in p["candidate_answers"]}
    for row, ident in zip(rows,ALL_KEYS):
        condition, label=ident.split("--")
        rendered="### Task:\n"+qs[condition]+"\n\n### Answer:\n"+ans[label]
        require(isinstance(row,dict)
                and set(row)=={
                    "id","condition","answer_id","question_sha256",
                    "answer_sha256","rendered_input_sha256","token_count",
                    "input_ids","source_commit",
                    "reference_is_independent_expert_gold",
                }
                and row["id"]==ident and row["condition"]==condition
                and row["answer_id"]==label
                and row["question_sha256"]==sha_text(qs[condition])
                and row["answer_sha256"]==sha_text(ans[label])
                and row["rendered_input_sha256"]==sha_text(rendered)
                and row["reference_is_independent_expert_gold"] is False
                and row["source_commit"]==(
                    p["source_parent_commit"] if condition=="code-context-a"
                    else p["source_fix_commit"] if condition=="code-context-b" else None
                )
                and type(row["token_count"]) is int
                and 12<=row["token_count"]<=TOKEN_CAP
                and isinstance(row["input_ids"],list)
                and len(row["input_ids"])==row["token_count"]
                and row["input_ids"][0]==50281 and row["input_ids"][-1]==50282
                and all(type(t) is int and 0<=t<50368 for t in row["input_ids"]),
                "original source/answer text or tokenizer input identity changed")
    return rows


def evaluate(p:dict, inputs:dict, packets:dict[str,dict])->dict:
    validate_inputs(inputs,p)
    require(isinstance(packets,dict) and len(packets)==6
            and set(packets)==set(ALL_KEYS),
            "missing, injected or duplicate REAL Foundation score packets")
    scores={}
    bits={}
    for ident in ALL_KEYS:
        actual=_score(packets[ident],ident)
        scores[ident]=actual["float32_value"]
        bits[ident]=actual["float32_score_hex"]
    conditions=[]
    for cond in CONDITIONS:
        a,b=scores[cond+"--A"],scores[cond+"--B"]
        predicted="A" if a>b else "B" if b>a else "TIE"
        expected=p["declared_source_fact_reference_labels"][cond]
        conditions.append({
            "condition":cond,
            "source_commit":p["source_parent_commit"] if cond=="code-context-a" else
                p["source_fix_commit"] if cond=="code-context-b" else None,
            "real_original_model_preference":predicted,
            "a_minus_b_float32_score_margin":a-b,
            "source_test_reproduced_researcher_reference":expected,
            "matches_original_executed_source_test_fact":
                (predicted==expected) if expected is not None else None,
            "independent_human_gold":None,
        })
    parent,fixed,without=conditions
    matched=sum(bool(row["matches_original_executed_source_test_fact"])
                for row in (parent,fixed))
    complete=matched==2
    changed=(parent["real_original_model_preference"] != fixed["real_original_model_preference"]
             and "TIE" not in (
                parent["real_original_model_preference"],fixed["real_original_model_preference"]
             ))
    return {
        "schema_version":1,"status":STATUS_RESULT,
        "original_model_sha256":MODEL_SHA,
        "original_foundation_sha256":FOUNDATION_SHA,
        "exact_official_tokenizer_sha256":TOKENIZER_SHA256,
        "frozen_protocol_git_blob_sha1":PROTOCOL_GIT_BLOB_SHA,
        "frozen_inputs_canonical_sha256":sha(canonical_json(inputs)),
        "pre_inference_source_selection_commit_verified":True,
        "actual_official_model_inference_verified":True,
        "actual_original_lora_model_score_inputs":6,
        "official_real_repeat_inference_calls":12,
        "original_upstream_source_pair":p["source_project"],
        "original_source_repair_test_run":p["verified_real_source_test_run"],
        "source_context_revision_facts":2,
        "original_model_fact_matches_out_of_two":matched,
        "real_model_changes_choice_with_source_revision":changed,
        "real_model_complete_correct_source_fact_reversal":complete,
        "no_source_control_preference":without["real_original_model_preference"],
        "no_source_control_has_no_gold_verdict":True,
        "constant_A_source_fact_matches":1,
        "constant_B_source_fact_matches":1,
        "source_conditions":conditions,
        "actual_float32_score_bits":bits,
        "original_lora_was_already_quarantined":True,
        "actual_improvement_to_trained_model":False,
        "not_blind_or_pretraining_disjoint":True,
        "independent_expert_gold_labels":0,
        "new_anjoman_eligible_rows":0,
        "model_registered":False,
        "automatic_registration_permitted":False,
        "official_H2_submission":False,
        "warning":(
            "Real unchanged original LoRA scoring on ONE already-public, new-to-the-"
            "old-model source project after frozen protocol selection. The source "
            "reference comes from original executable maintainer tests, NOT "
            "independent human adjudication. The no-source comparison has no "
            "valid fact label. Even perfect source agreement is neither a "
            "blind generalization rate nor improved trained model accuracy."
        )
    }


def write_once(path:Path,data:dict)->None:
    require(not path.exists() and not path.is_symlink(),"refuse overwrite evidence")
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(data,f,sort_keys=True,indent=2)
        f.write("\n")


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Original unchanged official Telegraph model sensitivity on public source repair")
    sub=parser.add_subparsers(dest="mode",required=True)
    prep=sub.add_parser("prepare")
    prep.add_argument("--upstream",type=Path,required=True)
    prep.add_argument("--tokenizer",type=Path,required=True)
    prep.add_argument("--out",type=Path,required=True)
    audit=sub.add_parser("audit")
    audit.add_argument("--inputs",type=Path,required=True)
    audit.add_argument("--scores-dir",type=Path,required=True)
    audit.add_argument("--out",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        p=protocol()
        source_lock=load_source_lock()
        require(source_lock["original_fixed_source_blob_sha1"]==
                p["source_blob_fixed"]
                and source_lock["original_parent_source_blob_sha1"]==
                p["source_blob_parent"],"Phase5L original proof no longer authentic")
        if args.mode=="prepare":
            verify_source(args.upstream,p)
            from tokenizers import Tokenizer
            tokenizer_raw=args.tokenizer.read_bytes()
            require(sha(tokenizer_raw)==TOKENIZER_SHA256,"real official tokenizer changed")
            tk=Tokenizer.from_str(tokenizer_raw.decode("utf-8"))
            result=make_inputs(p,tokenizer_raw,
                lambda text:tk.encode(text,add_special_tokens=True).ids)
            outputs=[(args.out,result)]
            for row in result["inputs"]:
                outputs.append((args.out.parent/("SCORE-"+row["id"]+".json"),{
                    "input_ids":row["input_ids"],
                    "attention_mask":[1]*row["token_count"],
                }))
            require(len({p.resolve() for p,_ in outputs})==len(outputs)
                    and not any(p.exists() or p.is_symlink() for p,_ in outputs),
                    "one or more original frozen score packets would be overwritten")
            for name,item in outputs:
                write_once(name,item)
            print(json.dumps({"status":result["status"],"real_score_inputs":6,
                              "original_source_facts_rechecked":True,
                              "no_gold_model_accuracy":True},sort_keys=True))
        else:
            inp=read_json(args.inputs.read_bytes())
            validate_inputs(inp,p)
            require(not args.out.exists() and not args.out.is_symlink(),"cannot overwrite score result")
            pkts={}
            for ident in ALL_KEYS:
                packet=args.scores_dir/ident/"OFFICIAL-SCORE.json"
                require(packet.is_file() and not packet.is_symlink(),"missing real original Foundation score: "+ident)
                require(packet.stat().st_size<12000,"unexpectedly large official score packet")
                pkts[ident]=read_json(packet.read_bytes())
            result=evaluate(p,inp,pkts)
            write_once(args.out,result)
            print(json.dumps({
                "real_original_lora_score_inputs":6,
                "actual_model_fact_matches":result["original_model_fact_matches_out_of_two"],
                "complete_source_sensitive_reversal":
                    result["real_model_complete_correct_source_fact_reversal"],
                "no_independent_gold":True,
            },sort_keys=True))
        return 0
    except (DiagnosticError,ScoreProofError,OSError,ValueError,TypeError,KeyError,
            UnicodeError,subprocess.SubprocessError) as err:
        parser.exit(1,"FALSUM PHASE5M AUTHENTIC ORIGINAL MODEL PROBE BLOCKED: "
                    +str(err)[:240]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
