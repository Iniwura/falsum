"""Reproducible *researcher-operated* inference on a published, independently
authored, open-weight model using FALSUM's existing frozen public source task.

Not a Telegraph adapter/registration, independent human review, hidden gold,
external customer adoption, independent run, or training improvement. Real
weights must be downloaded and loaded; unit tests only validate envelopes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from .phase5l_pymdown_upstream_replay import git_blob
from .phase5m_real_source_sensitive_model import (
    ROOT, DiagnosticError, read_json, require, canonical_json, sha
)
from .phase5m_source_context_candidate import construct, score, ALLOWED, template, validate

LOCK_PATH="data/phase5n-published-small-model-prediction-protocol.json"
LOCK_SHA="dddd564b4276c4f4ee7f60058594eda1d7cfbbae"
INPUT_STATUS="PHASE5N_PRE_SCORING_FROZEN_RESEARCHER_OPERATED_PUBLISHED_MODEL_PROMPTS"
RAW_STATUS="PHASE5N_ACTUAL_RESEARCHER_OPERATED_PUBLISHED_MODEL_INFERENCE_NOT_ADOPTION"
RESULT_STATUS="PHASE5N_RESEARCHER_OPERATED_PUBLISHED_MODEL_SOURCE_DIAGNOSTIC_NOT_GOLD"
MODEL_REPO="Qwen/Qwen2.5-0.5B-Instruct"
SHA40=re.compile(r"^[0-9a-f]{40}$")
WHITELIST=(
    "config.json","generation_config.json","tokenizer.json",
    "tokenizer_config.json","special_tokens_map.json","vocab.json",
    "merges.txt","model.safetensors","model.safetensors.index.json",
    "model-*.safetensors",
)
DECISIONS=("A","B","ABSTAIN","INVALID")


def freeze(root:Path=ROOT)->dict:
    raw=(root/LOCK_PATH).read_bytes()
    require(0<len(raw)<10000 and git_blob(raw)==LOCK_SHA,"model choice protocol was changed AFTER freeze")
    x=read_json(raw)
    require(type(x.get("schema_version")) is int and x["schema_version"]==1
            and x.get("status")==
              "PHASE5N_FROZEN_RESEARCHER_OPERATED_EXTERNAL_PUBLISHED_MODEL_BASELINE_NOT_INDEPENDENT_ADOPTION"
            and x.get("intended_intent")=="SECURITY_REVIEW_GENERAL"
            and x.get("model_repository")==MODEL_REPO
            and x.get("model_revision_policy","").startswith("Resolve public Hugging Face")
            and x.get("source_challenge_generator")=="src/falsum/phase5m_source_context_candidate.py"
            and x.get("original_source_model_protocol_git_blob_sha1")==
                "b50c6e1ad386f4bbf2faa7dd15ddba35b860f9b3"
            and x.get("real_source_replay_run")==44716279199
            and x.get("model_provider","").startswith("Qwen, publicly authored")
            and x.get("execution_backend","").startswith("transformers AutoModelForCausalLM CPU")
            and x.get("system_instruction","").endswith("No explanation.")
            and x.get("generation_max_new_tokens")==12
            and type(x["generation_max_new_tokens"]) is int
            and x.get("generate_do_sample") is False
            and x.get("max_input_tokens")==1024
            and x.get("total_public_source_questions")==3
            and x.get("run_all_questions_regardless_of_errors") is True
            and x.get("no_few_shot_examples") is True
            and x.get("actual_source_reference_labels_are_public_researcher_constructed") is True
            and x.get("prior_model_checkpoint_missing") is True
            and x.get("prior_original_lora_not_retrained_or_loaded") is True
            and x.get("independent_qualified_appsec_adjudications")==0
            and x.get("external_independent_developer_adoption")==0
            and x.get("network_evaluator_registered") is False
            and x.get("anjoman_new_eligible_rows")==0
            and x.get("entry_submitted") is False
            and x.get("accepted_h2_prize_or_winning_claim") is False,
            "unfrozen or inflated model experiment")
    t=x.get("user_instruction_template")
    require(isinstance(t,str)
            and all(x in t for x in (
                "{question}","{candidate_A}","{candidate_B}"
            ))
            and isinstance(x.get("system_instruction"),str),
            "pre-scoring question or model instruction missing")
    return x


def prepare(root:Path=ROOT)->dict:
    p=freeze(root)
    challenge,_,_=construct(root)
    questions=[]
    for q in challenge["questions"]:
        text=p["user_instruction_template"].replace("\\n","\n")
        a,b=[x["text"] for x in q["answer_options"]]
        rendered=(text.replace("{question}",q["question"])
                  .replace("{candidate_A}",a).replace("{candidate_B}",b))
        require(120<len(rendered)<4200 and q["id"] not in rendered,
                "code-context prompt damaged or answer lookup leaked")
        questions.append({
            "id":q["id"],"messages":[
                {"role":"system","content":p["system_instruction"]},
                {"role":"user","content":rendered},
            ],
            "question_sha256":sha(q["question"].encode()),
            "source_file_commit":q["source_git_sha"],
        })
    require(len(questions)==3 and len({q["id"] for q in questions})==3,
            "must attempt all three original public source questions")
    return {
        "schema_version":1,
        "status":INPUT_STATUS,
        "frozen_model_selection_git_blob":LOCK_SHA,
        "model_repository":MODEL_REPO,
        "challenge_sha256":sha(canonical_json(challenge)),
        "original_upstream_replay_run":44716279199,
        "public_source_question_count":3,
        "source_condition_count":2,"source_omitted_control_count":1,
        "questions":questions,
        "researcher_constructed_open_book":True,
        "independent_appsec_gold":0,"candidate_external_adoption":False,
        "historical_telegraph_lora_unchanged_and_unavailable":True,
        "model_inference_performed":False,
    }


def parse_choice(raw:str)->str:
    require(isinstance(raw,str) and len(raw)<2000,"malformed raw model reply")
    normalized=raw.strip().upper()
    normalized=normalized.strip(" .:*!'\`\"()")
    if normalized in ALLOWED:
        return normalized
    # No heuristic extraction from explanations: failure to respect the forced
    # output schema is measured as INVALID, not coerced to the correct label.
    return "INVALID"


def validate_prepared(doc:dict,expected:dict)->None:
    require(doc==expected
            and type(doc.get("schema_version")) is int,
            "published model input prompt or original source challenge has changed")


def audit(original:dict,prepared:dict,challenge:dict,refs:dict,conditions:dict)->dict:
    validate_prepared(prepared,prepare())
    require(isinstance(original,dict)
            and original.get("status")==RAW_STATUS
            and type(original.get("schema_version")) is int
            and original["schema_version"]==1
            and original.get("model_repository")==MODEL_REPO
            and isinstance(original.get("model_revision"),str)
            and SHA40.fullmatch(original["model_revision"])
            and original.get("frozen_model_selection_git_blob")==LOCK_SHA
            and original.get("challenge_sha256")==sha(canonical_json(challenge))
            and original.get("prepared_prompt_sha256")==sha(canonical_json(prepared))
            and original.get("pretrained_published_model_loaded") is True
            and original.get("greedy_deterministic_decode") is True
            and original.get("actual_question_forward_passes")==3
            and original.get("run_all_precommitted_three_questions") is True
            and original.get("source_references_not_used_during_generation") is True
            and original.get("researcher_operated_not_independent_adoption") is True
            and original.get("historical_telegraph_lora_not_used") is True
            and original.get("no_training_or_finetuning") is True
            and original.get("independent_appsec_gold")==0
            and original.get("model_registered") is False
            and original.get("entry_submitted") is False,
            "candidate raw packet has no original published-model evidence")
    hashes=original.get("downloaded_model_file_sha256")
    require(isinstance(hashes,dict) and len(hashes)>=3
            and "config.json" in hashes
            and "tokenizer.json" in hashes
            and any(k.endswith(".safetensors") for k in hashes)
            and all(isinstance(v,str) and re.fullmatch(r"[0-9a-f]{64}",v)
                    for v in hashes.values()),
            "published model config/tokenizer/safetensors file fingerprints missing")
    predictions=original.get("predictions")
    require(isinstance(predictions,list) and len(predictions)==3
            and [x.get("id") for x in predictions]==[
                q["id"] for q in prepared["questions"]
            ],"required real same-order model responses missing")
    require(all(
        isinstance(x,dict) and
        set(x)=={"id","raw_completion","parsed_choice","input_tokens","output_tokens"}
        and isinstance(x["raw_completion"],str) and len(x["raw_completion"])<2000
        and x["parsed_choice"]==parse_choice(x["raw_completion"])
        and type(x["input_tokens"]) is int and 0<x["input_tokens"]<=1024
        and type(x["output_tokens"]) is int and 0<x["output_tokens"]<=12
        for x in predictions
    ),"unverified raw completion/choice/real decode length")
    choices={x["id"]:x["parsed_choice"] for x in predictions}
    valid={k:v for k,v in choices.items() if v in ALLOWED}
    total_correct=sum(choices[k]==refs[k] for k in refs)
    fact_ids=[k for k,r in conditions.items() if r in ("code-context-a","code-context-b")]
    no_source_ids=[k for k,r in conditions.items() if r=="source-omitted"]
    require(len(fact_ids)==2 and len(no_source_ids)==1,"source/no-source diagnostic count changed")
    # Existing original public scorer is only usable if ALL real replies obeyed
    # its structured protocol. An invalid reply is a logged failure, not abstain.
    if len(valid)==3:
        source=score(challenge,refs,conditions,valid,
                     origin="RESEARCHER_OPERATED_PUBLISHED_OPEN_WEIGHT_MODEL")
        require(source["questions_scored"]==3,"external-compatible scorer drift")
        full_reversal=source["source_sensitive_complete_correct_reversal"]
        abstained=source["no_source_control_abstained"]
    else:
        source=None
        full_reversal=all(choices[k]==refs[k] for k in fact_ids)
        abstained=choices[no_source_ids[0]]=="ABSTAIN"
    require(total_correct<=len(valid),"INVALID completion cannot be correct")
    return {
        "schema_version":1,"status":RESULT_STATUS,
        "model_repository":MODEL_REPO,
        "model_revision":original["model_revision"],
        "model_sha256_by_file":hashes,
        "original_experiment_github_run":original.get("github_run_url"),
        "published_model_user_prompt_sha256":sha(canonical_json(prepared)),
        "source_reference_sha256":sha(canonical_json(challenge)),
        "model_run_real_not_simulated":True,
        "valid_structured_model_choices":len(valid),
        "invalid_model_choices":3-len(valid),
        "all_three_original_questions_attempted":True,
        "original_public_source_reference_matches":total_correct,
        "source_fact_matches_out_of_two":sum(choices[k]==refs[k] for k in fact_ids),
        "correct_complete_source_revision_reversal":full_reversal,
        "no_source_control_abstained":abstained,
        "constant_A_source_reference_matches":1,
        "constant_B_source_reference_matches":1,
        "constant_ABSTAIN_source_reference_matches":1,
        "candidate_public_evaluator_score":source,
        "raw_original_model_outputs":predictions,
        "provenance":"RESEARCHER_EXECUTED_PUBLISHED_THIRD_PARTY_OPEN_WEIGHT_MODEL_NOT_EXTERNAL_ADOPTION",
        "statistically_valid_general_security_evaluator_accuracy":False,
        "independent_expert_gold":0,
        "real_independent_external_developer_adoption":False,
        "this_is_not_a_telegraph_scorer_or_registered_adapter":True,
        "trained_model_improvement":False,
        "historical_lora_checkpoint_restored":False,
        "eligible_anjoman_new_rows":0,
        "official_h2_entry_submitted":False,
        "limitation":"One public source pair, one no-source control, researcher-operated off-network small model; public authored reference, no qualified human labels or hidden holdout. Model was not trained by FALSUM. Results must be described as a candidate diagnostic, never published as general accuracy or independent third-party adoption."
    }


def write_once(path:Path,obj:dict)->None:
    require(not path.exists() and not path.is_symlink(),"write-once evidence path already exists")
    path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        json.dump(obj,f,sort_keys=True,indent=2)
        f.write("\n")


def get_sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()


def actual_inference(prepared:dict)->dict:
    """Loads REAL immutable HF checkpoint. NEVER returns synthetic model data."""
    import torch
    from huggingface_hub import HfApi, snapshot_download
    from transformers import AutoTokenizer, AutoModelForCausalLM
    p=freeze()
    api=HfApi()
    info=api.model_info(MODEL_REPO)
    revision=info.sha
    require(isinstance(revision,str) and SHA40.fullmatch(revision) is not None
            and info.id==MODEL_REPO,
            "published HF model ID or revision unresolved")
    location=Path(snapshot_download(
        repo_id=MODEL_REPO,revision=revision,
        allow_patterns=list(WHITELIST),
        max_workers=2,
    ))
    files={}
    for path in sorted(location.iterdir()):
        if path.is_file() and path.name in (
            "config.json","generation_config.json","tokenizer.json",
            "tokenizer_config.json","special_tokens_map.json",
            "vocab.json","merges.txt","model.safetensors",
            "model.safetensors.index.json",
        ):
            files[path.name]=get_sha256_file(path)
        elif path.is_file() and re.fullmatch(r"model-[0-9]+-of-[0-9]+\.safetensors",path.name):
            files[path.name]=get_sha256_file(path)
    require("config.json" in files and "tokenizer.json" in files
            and any(key.endswith(".safetensors") for key in files),
            "downloaded publisher model/tokenizer weights missing; no fake scoring allowed")
    torch.set_num_threads(2)
    model=AutoModelForCausalLM.from_pretrained(
        str(location),trust_remote_code=False,
        local_files_only=True,use_safetensors=True,
        torch_dtype=torch.float32,
    ).eval()
    tokenizer=AutoTokenizer.from_pretrained(
        str(location),trust_remote_code=False,local_files_only=True,
    )
    require(len(prepared["questions"])==3,"three frozen questions missing")
    records=[]
    for row in prepared["questions"]:
        messages=row["messages"]
        inputs=tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt"
        )
        ntokens=int(inputs.shape[-1])
        require(0<ntokens<=p["max_input_tokens"],
                "source question silently exceeds frozen model token cap")
        with torch.inference_mode():
            output=model.generate(
                inputs,
                max_new_tokens=p["generation_max_new_tokens"],
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        produced=output[0,inputs.shape[-1]:]
        raw=tokenizer.decode(produced,skip_special_tokens=True)
        records.append({
            "id":row["id"],
            "raw_completion":raw,
            "parsed_choice":parse_choice(raw),
            "input_tokens":ntokens,
            "output_tokens":int(produced.numel()),
        })
    require(len(records)==3,"not all frozen source conditions executed")
    return {
        "schema_version":1,"status":RAW_STATUS,
        "model_repository":MODEL_REPO,"model_revision":revision,
        "downloaded_model_file_sha256":files,
        "frozen_model_selection_git_blob":LOCK_SHA,
        "challenge_sha256":prepared["challenge_sha256"],
        "prepared_prompt_sha256":sha(canonical_json(prepared)),
        "pretrained_published_model_loaded":True,
        "greedy_deterministic_decode":True,
        "actual_question_forward_passes":3,
        "run_all_precommitted_three_questions":True,
        "source_references_not_used_during_generation":True,
        "researcher_operated_not_independent_adoption":True,
        "historical_telegraph_lora_not_used":True,
        "no_training_or_finetuning":True,
        "independent_appsec_gold":0,
        "model_registered":False,
        "entry_submitted":False,
        "github_run_url":(
            "https://github.com/Iniwura/falsum/actions/runs/"+os.environ["GITHUB_RUN_ID"]
            if "GITHUB_RUN_ID" in os.environ else None
        ),
        "predictions":records,
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Actual published-model provenance and paired source sensitivity; NOT independent expert labels")
    sub=parser.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("prepare")
    p.add_argument("--out",type=Path,required=True)
    e=sub.add_parser("execute")
    e.add_argument("--inputs",type=Path,required=True)
    e.add_argument("--out",type=Path,required=True)
    a=sub.add_parser("audit")
    a.add_argument("--inputs",type=Path,required=True)
    a.add_argument("--actual",type=Path,required=True)
    a.add_argument("--out",type=Path,required=True)
    opt=parser.parse_args(argv)
    try:
        prepared=prepare()
        if opt.cmd=="prepare":
            write_once(opt.out,prepared)
            print(json.dumps({"frozen_public_source_questions":3,"public_model":MODEL_REPO,
                              "training":False,"actual_model_inference":False}))
        else:
            doc=read_json(opt.inputs.read_bytes())
            validate_prepared(doc,prepared)
            if opt.cmd=="execute":
                actual=actual_inference(prepared)
                write_once(opt.out,actual)
                print(json.dumps({"model_revision":actual["model_revision"],
                                  "generated_predictions":[p["parsed_choice"] for p in actual["predictions"]],
                                  "model_was_loaded":True}))
            else:
                real=read_json(opt.actual.read_bytes())
                challenge,refs,conditions=construct()
                result=audit(real,prepared,challenge,refs,conditions)
                write_once(opt.out,result)
                print(json.dumps({"actual_model_scored":True,
                                  "matches":result["original_public_source_reference_matches"],
                                  "total":3,"correct_reversal":result["correct_complete_source_revision_reversal"],
                                  "external_adoption":False},sort_keys=True))
        return 0
    except (DiagnosticError,OSError,ValueError,TypeError,KeyError,UnicodeError) as exc:
        parser.exit(1,"PHASE5N ACTUAL PUBLISHED MODEL (NOT TELEGRAPH) FAILED CLOSED: "
                    +str(exc)[:270]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
