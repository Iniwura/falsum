"""Phase 5W: ACTUAL original immutable publisher inference on four NEW source projects.

This is a researcher-operated open-weight model diagnostic. Every source code
and original upstream test file is SHA-verified via Phase 5U before model
inference. Frozen model selection, greedy decoding and prompts are never
adjusted after viewing model predictions.

An original negative result MUST be preserved. Author-selected public
references, not independent AppSec gold or Telegraph network model rankings.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re

from .phase5l_pymdown_upstream_replay import git_blob
from .phase5m_real_source_sensitive_model import ROOT, DiagnosticError, require, read_json, canonical_json, sha
from .phase5n_published_candidate_runner import (
    WHITELIST, parse_choice, get_sha256_file,
)
from .phase5u_project_disjoint_security import (
    LOCK_GIT_BLOB as SOURCE_GIT_BLOB, challenge as source_challenge,
    score as source_score, baseline as source_baseline, ident, PROJECTS,
)
from .phase5o_four_project_published_model import (
    MODEL_REVISION, MODEL_SAFETENSORS_SHA256,
)

FROZEN_FILE="data/phase5w-preregistered-published-model-new-source.json"
FROZEN_BLOB="c8ce938f914ec8c1c481ff193d6c3db98aa86ed0"
MODEL_REPO="Qwen/Qwen2.5-0.5B-Instruct"
ST_RAW="PHASE5W_ACTUAL_PUBLISHED_QWEN_0P5B_ORIGINAL_NEW_UPSTREAM_SOURCE_INFERENCE"
ST_AUDIT="PHASE5W_MEASURED_ORIGINAL_NEW_PROJECT_SOURCE_MODEL_FAILURE_OR_SUCCESS"
MAX_OUTPUT=12
MAX_INPUT=1024


def frozen(root:Path=ROOT)->dict:
    raw=(root/FROZEN_FILE).read_bytes()
    require(git_blob(raw)==FROZEN_BLOB,
            "new security source model study or prompt changed after preregistration")
    p=read_json(raw)
    require(p.get("schema_version")==1 and
            p.get("status")==
                "PHASE5W_FROZEN_ORIGINAL_NEW_PROJECT_PUBLIC_MODEL_INFERENCE_BEFORE_ANY_FORWARD_PASSES"
            and p.get("source_project_lock_git_blob_sha1")==SOURCE_GIT_BLOB
            and p.get("source_projects")==list(PROJECTS)
            and p.get("source_present_tasks")==16
            and p.get("source_absent_tasks")==8
            and p.get("all_tasks")==24
            and p.get("selected_published_model")==MODEL_REPO
            and p.get("pinned_original_publisher_revision")==MODEL_REVISION
            and p.get("pinned_original_safetensors_sha256")==MODEL_SAFETENSORS_SHA256
            and p.get("model_forward_passes_required")==24
            and p.get("generation_max_new_tokens")==MAX_OUTPUT
            and p.get("input_tokens_limit")==MAX_INPUT
            and p.get("no_few_shot_examples") is True
            and p.get("greedy_decode_only") is True
            and p.get("input_messages_original_unmodified") is True
            and p.get("raw_outputs_must_be_preserved") is True
            and p.get("independent_appsec_expert_gold_count")==0
            and p.get("model_training_performed") is False
            and p.get("registered_network_evaluator") is False
            and p.get("paid_network_requests")==0
            and p.get("independent_external_developer_adoption") is False
            and p.get("official_h2_submitted") is False
            and p.get("no_model_score_or_positive_result_asserted_before_actual_inference") is True,
            "new source model evaluation, scoring or no-gold commitment changed")
    return p


def prepare(*,downloader=None,root:Path=ROOT)->tuple[dict,dict[str,str]]:
    frozen(root)
    # The actual full original source and upstream test Git blob SHA validation
    # is performed by Phase 5U's immutable original upstream code reader.
    if downloader is None:
        return source_challenge(root=root)[:2]
    return source_challenge(root=root,downloader=downloader)[:2]


def real_inference(doc:dict,*,root:Path=ROOT)->dict:
    frozen(root)
    require(doc.get("status")==
                "PHASE5U_ORIGINAL_GIT_AUTHENTICATED_FOUR_NEW_PROJECTS_PUBLIC_24_SOURCE_CONDITIONS"
            and len(doc.get("questions",[]))==24
            and doc.get("original_code_git_blob_verified")==8
            and doc.get("original_upstream_test_git_blob_verified")==8,
            "source challenge must be original new four-project Git verified 24 questions")
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoModelForCausalLM,AutoTokenizer
    folder=Path(snapshot_download(
        repo_id=MODEL_REPO,revision=MODEL_REVISION,
        allow_patterns=list(WHITELIST),max_workers=2))
    hashes={}
    for file in sorted(folder.iterdir()):
        if file.is_file() and file.name in (
            "config.json","generation_config.json","tokenizer.json",
            "tokenizer_config.json","special_tokens_map.json",
            "vocab.json","merges.txt","model.safetensors"):
            hashes[file.name]=get_sha256_file(file)
    require(hashes.get("model.safetensors")==MODEL_SAFETENSORS_SHA256
            and re.fullmatch(r"[0-9a-f]{64}",hashes.get("tokenizer.json",""))
            and re.fullmatch(r"[0-9a-f]{64}",hashes.get("config.json","")),
            "original immutable published model/tokenizer checkpoint not verified")
    torch.set_num_threads(2)
    model=AutoModelForCausalLM.from_pretrained(
        str(folder),trust_remote_code=False,local_files_only=True,
        use_safetensors=True,torch_dtype=torch.float32).eval()
    tokenizer=AutoTokenizer.from_pretrained(
        str(folder),trust_remote_code=False,local_files_only=True)
    outputs=[]
    for question in doc["questions"]:
        messages=question["messages"]
        require(isinstance(messages,list) and len(messages)==2
                and messages[0]["role"]=="system"
                and messages[1]["role"]=="user"
                and sha(messages[1]["content"].encode("utf-8"))==question["prompt_sha256"],
                "original source code prompt differs from frozen data")
        inputs=tokenizer.apply_chat_template(messages,
                  add_generation_prompt=True,return_tensors="pt")
        tokens=int(inputs.shape[-1])
        require(0<tokens<=MAX_INPUT,"original source prompt exceeds frozen model input; do not truncate")
        with torch.inference_mode():
            generated=model.generate(inputs,max_new_tokens=MAX_OUTPUT,do_sample=False,
                pad_token_id=tokenizer.eos_token_id)
        decoded=generated[0,inputs.shape[-1]:]
        raw=tokenizer.decode(decoded,skip_special_tokens=True)
        outputs.append({
            "id":question["id"],"input_tokens":tokens,
            "output_tokens":int(decoded.numel()),
            "raw_completion":raw,"parsed_choice":parse_choice(raw),
        })
    require(len(outputs)==24,"actual model forward pass count incomplete")
    return {
        "schema_version":1,"status":ST_RAW,
        "model_repository":MODEL_REPO,
        "original_publisher_immutable_revision":MODEL_REVISION,
        "original_publisher_files_sha256":hashes,
        "original_model_safetensors_sha256":hashes["model.safetensors"],
        "preinference_protocol_git_blob_sha1":FROZEN_BLOB,
        "new_project_original_source_lock_git_blob_sha1":SOURCE_GIT_BLOB,
        "original_source_challenge_sha256":sha(canonical_json(doc)),
        "actual_original_published_model_forward_passes":24,
        "actual_model_loaded_from_original_publisher":True,
        "no_few_shot_or_prompt_tuning":True,
        "greedy_decode":True,"original_input_questions_unchanged":True,
        "researcher_operated_not_independent_review":True,
        "independent_appsec_gold_count":0,
        "registered_network_evaluator":False,
        "new_paid_telegraph_requests":0,
        "h2_officially_submitted":False,
        "original_github_run_url":(
            "https://github.com/Iniwura/falsum/actions/runs/"+os.environ["GITHUB_RUN_ID"]
            if "GITHUB_RUN_ID" in os.environ else None),
        "predictions":outputs,
    }


def audit(doc:dict,references:dict[str,str],raw:dict,*,root:Path=ROOT)->dict:
    frozen(root)
    require(isinstance(raw,dict)
            and raw.get("schema_version")==1 and raw.get("status")==ST_RAW
            and raw.get("model_repository")==MODEL_REPO
            and raw.get("original_publisher_immutable_revision")==MODEL_REVISION
            and raw.get("original_model_safetensors_sha256")==MODEL_SAFETENSORS_SHA256
            and raw.get("preinference_protocol_git_blob_sha1")==FROZEN_BLOB
            and raw.get("new_project_original_source_lock_git_blob_sha1")==SOURCE_GIT_BLOB
            and raw.get("original_source_challenge_sha256")==sha(canonical_json(doc))
            and raw.get("actual_original_published_model_forward_passes")==24
            and raw.get("actual_model_loaded_from_original_publisher") is True
            and raw.get("no_few_shot_or_prompt_tuning") is True
            and raw.get("greedy_decode") is True
            and raw.get("original_input_questions_unchanged") is True
            and raw.get("researcher_operated_not_independent_review") is True
            and raw.get("independent_appsec_gold_count")==0
            and raw.get("registered_network_evaluator") is False
            and raw.get("new_paid_telegraph_requests")==0
            and raw.get("h2_officially_submitted") is False,
            "claimed original 24 model pass provenance/identity not verified")
    files=raw.get("original_publisher_files_sha256")
    require(isinstance(files,dict) and files.get("model.safetensors")==
            MODEL_SAFETENSORS_SHA256
            and "tokenizer.json" in files and "config.json" in files
            and all(isinstance(x,str) and re.fullmatch(r"[0-9a-f]{64}",x)
                    for x in files.values()),
            "original immutable model file SHA identities unavailable")
    rows=raw.get("predictions")
    require(isinstance(rows,list) and len(rows)==24 and
            [row.get("id") for row in rows]==[q["id"] for q in doc["questions"]],
            "24 actual published model predictions missing, duplicated or swapped")
    for row in rows:
        require(isinstance(row,dict)
                and set(row)=={"id","input_tokens","output_tokens","raw_completion","parsed_choice"}
                and type(row["input_tokens"]) is int and 0<row["input_tokens"]<=MAX_INPUT
                and type(row["output_tokens"]) is int and 0<row["output_tokens"]<=MAX_OUTPUT
                and isinstance(row["raw_completion"],str)
                and len(row["raw_completion"])<1000
                and row["parsed_choice"]==parse_choice(row["raw_completion"]),
                "actual raw model response invalid or choice parsing misrepresented")
    pred={row["id"]:row["parsed_choice"] for row in rows}
    metric=source_score(references,pred,
                        origin="UNVERIFIED_EXTERNAL_PUBLIC_CANDIDATE")
    # Above source scoreboard has a pessimistic candidate metadata flag. This
    # audited wrapper verifies original model files, actual 24 passes and
    # original raw responses. That only proves researcher-operated inference,
    # NOT independent validation of the researcher-selected reference gold.
    blind=source_score(references,source_baseline(),
                       origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")
    all_abstain=source_score(references,{k:"ABSTAIN" for k in references},
                       origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")
    return {
        "schema_version":1,"status":ST_AUDIT,
        "immutable_original_publisher_weights_sha256":MODEL_SAFETENSORS_SHA256,
        "original_immutable_publisher_revision":MODEL_REVISION,
        "original_full_git_source_challenge_sha256":sha(canonical_json(doc)),
        "preinference_git_blob_sha1":FROZEN_BLOB,
        "actual_original_model_forward_passes":24,
        "model_predictions_researcher_operated_and_real":True,
        "model_raw_completions_preserved":rows,
        "measured_original_public_model":metric,
        "prompt_only_source_blind_disclosed_synthetic":blind,
        "always_abstain_disclosed_synthetic":all_abstain,
        "published_model_vs_blind_reference_match_delta":
            metric["matches_to_researcher_derived_public_references"]-
            blind["matches_to_researcher_derived_public_references"],
        "actual_source_present_matches":metric["source_present_matches"],
        "actual_complete_source_and_answer_order_reversals":
            metric["complete_correct_four_way_source_and_answer_reversals"],
        "casebook_open_book_prior_public_security_fixes":True,
        "historical_original_source_authenticity_verified":True,
        "historical_upstream_test_file_authenticity_verified":True,
        "entire_original_upstream_suites_executed_for_this_model_study":False,
        "model_training_performed":False,
        "independent_appsec_expert_gold":0,
        "independent_external_adoption":False,
        "real_telegraph_multi_miner_ranking_improved":False,
        "registered_telegraph_evaluator":False,
        "official_h2_entry_submitted":False,
    }


def write_once(path:Path,obj:dict)->None:
    require(path.suffix.lower()==".json" and not path.exists() and
            not path.is_symlink(),"original published model artifact must be fresh JSON")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as file:
        json.dump(obj,file,sort_keys=True,indent=2,ensure_ascii=False)
        file.write("\n")


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Actually infer pinned published Qwen over four new source-project tests, preserve raw failures")
    subs=p.add_subparsers(dest="mode",required=True)
    for mode in ("infer","audit"):
        q=subs.add_parser(mode)
        q.add_argument("--out",required=True,type=Path)
        if mode=="audit":
            q.add_argument("--raw",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        challenge,refs=prepare()
        if args.mode=="infer":
            report=real_inference(challenge)
        else:
            require(args.raw.exists() and not args.raw.is_symlink() and
                    0<args.raw.stat().st_size<=100000,
                    "original full inference artifact not present or oversized")
            report=audit(challenge,refs,read_json(args.raw.read_bytes()))
        write_once(args.out,report)
        print(json.dumps({
            "status":report["status"],
            "original_model_forward_passes":report.get(
                "actual_original_published_model_forward_passes",
                report.get("actual_original_model_forward_passes")),
            "model_matches":report.get("measured_original_public_model",{}).get(
                "matches_to_researcher_derived_public_references"),
            "source_present_matches":report.get("actual_source_present_matches"),
            "full_source_and_answer_order_reversals":report.get(
                "actual_complete_source_and_answer_order_reversals"),
            "independent_appsec_gold":0,"trained_model":False,
        },sort_keys=True))
        return 0
    except (OSError,UnicodeError,ValueError,TypeError,KeyError,
            AssertionError,DiagnosticError) as error:
        p.exit(1,"PHASE5W REAL ORIGINAL PUBLISHER MODEL FAILED CLOSED: "+
               str(error)[:250]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
