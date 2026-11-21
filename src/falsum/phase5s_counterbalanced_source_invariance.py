"""Phase 5S: counterbalanced source-sensitive paired evaluation, prompt-only blind bounds.

Honest scope: four *previously researched* public upstream code projects; researcher
reference answers; no expert gold, trained model, registered network scorer or
secret holdout. Actual model forward passes run only via explicit infer mode.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re

from . import phase5p_raw_code_evaluator as p5
from .phase5m_real_source_sensitive_model import ROOT, require, read_json, canonical_json, sha
from .phase5n_published_candidate_runner import (
    WHITELIST, parse_choice, write_once, get_sha256_file,
)
from .phase5o_four_project_published_model import MODEL_SAFETENSORS_SHA256

LOCK_PATH="data/phase5s-preinference-four-way-source-reversal.json"
LOCK_SHA1="5d7dff79205c24d465d71d45d4457b0ff992b67d"
ST_CHALLENGE="PHASE5S_AUTHENTIC_OPEN_BOOK_24_COUNTERBALANCED_CODE_CONDITIONS"
ST_TEMPLATE="PHASE5S_UNVERIFIED_CANDIDATE_PREDICTIONS"
ST_RAW="PHASE5S_ORIGINAL_REAL_PUBLISHED_MODEL_24_SOURCE_FORWARD_PASSES"
ST_AUDIT="PHASE5S_COUNTERBALANCED_SOURCE_REVERSAL_REAL_MODEL_DIAGNOSTIC"
PROJECTS=p5.PROJECTS
CONDS=("parent","fixed","source-omitted")
POSITIONS=("original-order","swapped-order")
LABELS=("A","B","ABSTAIN")
ALL_LABELS=("A","B","ABSTAIN","INVALID")
MODEL_CHOICES={
    "small":("Qwen/Qwen2.5-0.5B-Instruct","7ae557604adf67be50417f59c2c2f167def9a775"),
    "larger":("Qwen/Qwen2.5-1.5B-Instruct","989aa7980e4cf806f80c7fef2b1adb7bc71aa306"),
}


def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK_PATH).read_bytes()
    require(p5.git_blob(raw)==LOCK_SHA1,"Phase 5S original preinference policy changed")
    doc=read_json(raw)
    require(doc.get("status")=="PHASE5S_SOURCE_BLIND_PRIMARY_REVERSAL_PROTOCOL_FROZEN_BEFORE_NEW_MODEL_INFERENCE"
            and doc.get("phase5p_preinference_protocol_git_blob_sha1")==p5.PROTOCOL_BLOB
            and doc.get("phase4h_original_source_selection_git_blob_sha1")==p5.SOURCE_BLOB
            and doc.get("target_projects")==list(PROJECTS)
            and doc.get("number_of_tasks")==24
            and doc.get("exact_balanced_counts")=={"A":8,"B":8,"ABSTAIN":8}
            and doc.get("source_blind_primary_complete_reversal_upper_bound")==0
            and doc.get("source_blind_best_possible_total_matches")==16
            and doc.get("greedy_decode") is True
            and doc.get("max_generated_tokens")==12
            and doc.get("max_input_tokens")==1024
            and doc.get("independent_appsec_gold")==0
            and doc.get("no_hidden_model_holdout") is True
            and doc.get("no_new_project_claim") is True
            and doc.get("no_new_live_telegraph_model_ranking_claim") is True
            and doc.get("no_independent_adoption") is True
            and doc.get("registered_evaluator") is False
            and doc.get("no_h2_submission") is True
            and doc.get("original_weak_published_model")==MODEL_CHOICES["small"][0]
            and doc.get("weak_model_immutable_revision")==MODEL_CHOICES["small"][1]
            and doc.get("original_larger_published_model")==MODEL_CHOICES["larger"][0]
            and doc.get("larger_model_immutable_revision")==MODEL_CHOICES["larger"][1],
            "Phase 5S experiment or no-gold claims drifted")
    require(doc.get("comparison_conditions")==[
        "parent-original-order","parent-swapped-order",
        "fixed-original-order","fixed-swapped-order",
        "no-source-original-order","no-source-swapped-order"],
        "Phase 5S paired comparison design changed")
    require(doc.get("frozen_prompt_system","").startswith(
            "You are reviewing a security claim against exact supplied source code.")
            and doc["prompt_template"]==
            "Task: {question}\n\nSource code:\n{code}\n\nA. {answer_a}\nB. {answer_b}\n\nReturn exactly A, B, or ABSTAIN.",
            "public precommitted model prompt drifted")
    return doc


def ident(project:str,revision:str,position:str)->str:
    require(project in PROJECTS and revision in CONDS and position in POSITIONS,
            "invalid source condition identity")
    return hashlib.sha256(("phase5s/authenticated/public/"+project+"/"+
                    revision+"/"+position).encode()).hexdigest()[:32]


def prompt_parts(p:dict,question:str,code:str,a:str,b:str)->list[dict]:
    require(isinstance(question,str) and 40<len(question)<600
            and isinstance(code,str) and 25<len(code)<9000
            and isinstance(a,str) and isinstance(b,str)
            and 15<len(a)<900 and 15<len(b)<900,
            "source prompt cannot be truncated or malformed")
    user=(p["prompt_template"].replace("{question}",question)
          .replace("{code}",code).replace("{answer_a}",a).replace("{answer_b}",b))
    require("{" not in user and len(user)<12500,
            "placeholder injection or overly large prompt")
    return [{"role":"system","content":p["frozen_prompt_system"]},
            {"role":"user","content":user}]


def build(*,source_build=None,root:Path=ROOT)->tuple[dict,dict[str,str]]:
    p=frozen(root)
    phase5p_protocol,source=p5.frozen(root)
    if source_build is None:
        old,old_references=p5.build(root=root)
    else:
        old,old_references=source_build()
    require(old.get("status")==p5.ST_PREP
            and old.get("frozen_protocol_git_blob_sha1")==p5.PROTOCOL_BLOB
            and old.get("source_lock_git_blob_sha1")==p5.SOURCE_BLOB
            and old.get("source_files_downloaded_git_blob_verified") is True
            and old.get("reference_is_public_researcher_derived") is True
            and old.get("independent_appsec_gold")==0
            and len(old.get("questions",[]))==12,
            "original twelve source tasks not authenticated or public researcher derived")
    originals={item["id"]:item for item in old["questions"]}
    require(len(originals)==12 and len(old_references)==12,
            "original source question identities changed")
    rows=[]
    references={}
    for spec,case in zip(phase5p_protocol["project_specs"],source["cases"]):
        project=spec["key"]
        require(project==case["key"] and project in PROJECTS,
                "original source project order drift")
        for revision in CONDS:
            prior={"parent":"code-a","fixed":"code-b",
                   "source-omitted":"source-omitted"}[revision]
            q=originals[p5.ident(project,prior)]
            require((q["source_git_commit"] is None)==(revision=="source-omitted")
                    and sha(q["source_excerpt"].encode())==q["source_excerpt_sha256"]
                    and q["project"]==project,
                    "original code prompt revision or Git source identity differs")
            code=q["source_excerpt"]
            for position in POSITIONS:
                swapped=position=="swapped-order"
                option_a=case["b"] if swapped else case["a"]
                option_b=case["a"] if swapped else case["b"]
                messages=prompt_parts(p,spec["question"],code,option_a,option_b)
                label=("ABSTAIN" if revision=="source-omitted"
                       else ("A" if revision=="parent" else "B"))
                if swapped and label!="ABSTAIN":
                    label="B" if label=="A" else "A"
                key=ident(project,revision,position)
                references[key]=label
                rows.append({
                    # Model input is messages ONLY. No case/revision/role, URLs
                    # or position labels. IDs are public/open-book, not secret.
                    "id":key,
                    "messages":messages,
                    "prompt_sha256":sha(messages[1]["content"].encode()),
                })
    require(len(rows)==24 and len(references)==24 and
            len({x["id"] for x in rows})==24 and
            Counter(references.values())=={"A":8,"B":8,"ABSTAIN":8},
            "not the preregistered balanced 24 original source conditions")
    rows.sort(key=lambda q:hashlib.sha256(
        ("phase5s/public/order/"+q["id"]).encode()).hexdigest())
    # Security keys and revision mapping are in open-source code, but not
    # shipped as extra model-context metadata.
    challenge={
        "schema_version":1,"status":ST_CHALLENGE,
        "intent":"SECURITY_REVIEW_GENERAL",
        "phase5s_preinference_git_blob_sha1":LOCK_SHA1,
        "source_lock_git_blob_sha1":p5.SOURCE_BLOB,
        "source_code_files_full_git_blob_verified":8,
        "source_project_count":4,
        "question_count":24,
        "source_code_present_count":16,
        "source_omitted_controls":8,
        "reference_is_public_researcher_derived":True,
        "answer_key_included":False,
        "independent_security_expert_gold":0,
        "secret_private_holdout":False,
        "models_run_by_external_developer":False,
        "registered_network_evaluator":False,
        "questions":rows,
    }
    return challenge,references


def response_template(challenge:dict)->dict:
    return {"schema_version":1,"status":ST_TEMPLATE,
            "challenge_sha256":sha(canonical_json(challenge)),
            "decisions":[{"id":q["id"],"choice":None} for q in challenge["questions"]]}


def validate_responses(challenge:dict,submission:dict)->dict[str,str]:
    require(isinstance(submission,dict) and
            set(submission)=={"schema_version","status","challenge_sha256","decisions"}
            and submission["schema_version"]==1
            and type(submission["schema_version"]) is int
            and submission["status"]==ST_TEMPLATE
            and submission["challenge_sha256"]==sha(canonical_json(challenge)),
            "candidate response does not match exact immutable 24-prompt exercise")
    rows=submission["decisions"]
    require(isinstance(rows,list) and len(rows)==24,
            "twenty-four real candidate decisions required")
    decisions={}
    for expected,found in zip(challenge["questions"],rows):
        require(isinstance(found,dict) and set(found)=={"id","choice"}
                and found["id"]==expected["id"]
                and found["choice"] in LABELS,
                "candidate decisions reordered, duplicated, missing or invalid")
        decisions[expected["id"]]=found["choice"]
    require(len(decisions)==24,"duplicate candidate decision IDs")
    return decisions


def score(references:dict[str,str],predictions:dict[str,str],*,origin:str)->dict:
    require(origin in ("DISCLOSED_SYNTHETIC_BASELINE",
                      "RESEARCHER_OPERATED_REAL_PUBLISHED_MODEL",
                      "UNVERIFIED_SUBMITTED_CANDIDATE"),
            "source scoring provenance cannot be forged")
    require(len(references)==24 and set(references)==set(predictions)
            and Counter(references.values())=={"A":8,"B":8,"ABSTAIN":8}
            and all(choice in ALL_LABELS for choice in predictions.values()),
            "incomplete source-blind or model prediction set")
    confusion={lab:{prediction:0 for prediction in ALL_LABELS} for lab in LABELS}
    for k,ref in references.items():
        confusion[ref][predictions[k]]+=1
    complete=0
    correct_present=0
    correct_absent=0
    details={}
    for project in PROJECTS:
        chosen=[ident(project,rev,pos) for rev in ("parent","fixed") for pos in POSITIONS]
        absent=[ident(project,"source-omitted",pos) for pos in POSITIONS]
        pass_fourway=all(predictions[x]==references[x] for x in chosen)
        complete+=int(pass_fourway)
        correct_present+=sum(predictions[x]==references[x] for x in chosen)
        correct_absent+=sum(predictions[x]==references[x] for x in absent)
        details[project]={
            "four_way_source_and_position_counterfactual_correct":pass_fourway,
            "source_conditions_correct":sum(predictions[x]==references[x] for x in chosen),
            "no_source_conditions_correct":sum(predictions[x]==references[x] for x in absent),
        }
    return {
        "schema_version":1,"origin":origin,
        "total_questions":24,"authenticated_public_source_projects":4,
        "public_source_present_questions":16,"deliberately_source_omitted":8,
        "reference_distribution":{"A":8,"B":8,"ABSTAIN":8},
        "matches_to_public_researcher_references":correct_present+correct_absent,
        "complete_correct_four_way_source_and_position_reversals":complete,
        "source_present_matches":correct_present,
        "correct_no_source_abstentions":correct_absent,
        "unnecessary_abstentions_with_code":confusion["A"]["ABSTAIN"]+confusion["B"]["ABSTAIN"],
        "unsupported_confident_answers_no_source":confusion["ABSTAIN"]["A"]+confusion["ABSTAIN"]["B"],
        "invalid_outputs":sum(confusion[k]["INVALID"] for k in LABELS),
        "macro_class_recall":round(sum(confusion[k][k]/8 for k in LABELS)/3,6),
        "confusion_matrix_reference_by_predicted":confusion,
        "source_blind_prompt_only_upper_bound_total_matches":16,
        "source_blind_prompt_only_upper_bound_four_way_reversals":0,
        "always_abstain_baseline_matches":8,
        "always_A_baseline_matches":8,
        "always_B_baseline_matches":8,
        "source_blind_constant_code_choice_plus_no_source_abstain_matches":16,
        "public_answer_key_lookup_attacker_can_cheat":True,
        "independent_appsec_gold":0,"new_trained_scorer_proven":False,
        "registered_network_evaluator":False,"network_ranking_improved":False,
        "actual_external_developer_adoption":False,
        "official_h2_entry_submitted":False,
        "project_details":details,
    }


def source_blind_baseline()->dict[str,str]:
    return {ident(project,rev,pos):(
        "ABSTAIN" if rev=="source-omitted" else "A")
        for project in PROJECTS for rev in CONDS for pos in POSITIONS}


def infer(challenge:dict,model_key:str)->dict:
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoTokenizer, AutoModelForCausalLM
    p=frozen()
    require(model_key in MODEL_CHOICES,"unregistered model selection")
    repo,revision=MODEL_CHOICES[model_key]
    folder=Path(snapshot_download(repo_id=repo,revision=revision,
            allow_patterns=list(WHITELIST),max_workers=2))
    fingerprints={}
    for f in sorted(folder.iterdir()):
        if f.is_file() and (f.name in (
            "config.json","generation_config.json","tokenizer.json",
            "tokenizer_config.json","special_tokens_map.json","vocab.json",
            "merges.txt","model.safetensors","model.safetensors.index.json"
            ) or re.fullmatch(r"model-[0-9]+-of-[0-9]+\.safetensors",f.name)):
            fingerprints[f.name]=get_sha256_file(f)
    require("model.safetensors" in fingerprints
            and "config.json" in fingerprints and "tokenizer.json" in fingerprints
            and re.fullmatch(r"[0-9a-f]{64}",fingerprints["model.safetensors"]) is not None,
            "immutable original published model file is missing")
    if model_key=="small":
        require(fingerprints["model.safetensors"]==MODEL_SAFETENSORS_SHA256,
                "original 0.5B previously verified published checkpoint changed")
    torch.set_num_threads(2)
    dtype=torch.float32 if model_key=="small" else torch.bfloat16
    model=AutoModelForCausalLM.from_pretrained(
        str(folder),trust_remote_code=False,local_files_only=True,
        use_safetensors=True,torch_dtype=dtype).eval()
    tokenizer=AutoTokenizer.from_pretrained(str(folder),
        trust_remote_code=False,local_files_only=True)
    predictions=[]
    for question in challenge["questions"]:
        inputs=tokenizer.apply_chat_template(question["messages"],
                add_generation_prompt=True,return_tensors="pt")
        input_length=int(inputs.shape[-1])
        require(0<input_length<=p["max_input_tokens"],
                "authenticated original source task would be truncated")
        with torch.inference_mode():
            tokens=model.generate(inputs,max_new_tokens=p["max_generated_tokens"],
                   do_sample=False,pad_token_id=tokenizer.eos_token_id)
        completions=tokens[0,inputs.shape[-1]:]
        raw=tokenizer.decode(completions,skip_special_tokens=True)
        predictions.append({
            "id":question["id"],"input_tokens":input_length,
            "output_tokens":int(completions.numel()),
            "raw_completion":raw,"parsed_choice":parse_choice(raw),
        })
    require(len(predictions)==24,"not all original 24 model forward passes completed")
    return {
        "schema_version":1,"status":ST_RAW,
        "model_size_key":model_key,
        "original_publisher_model_repo":repo,"original_immutable_publisher_revision":revision,
        "publisher_model_file_sha256":fingerprints,
        "original_model_weight_sha256":fingerprints["model.safetensors"],
        "frozen_preinference_git_blob_sha1":LOCK_SHA1,
        "challenge_sha256":sha(canonical_json(challenge)),
        "actual_model_forward_passes":24,
        "original_published_model_loaded":True,
        "no_test_labels_given_to_model":True,
        "no_model_training_or_prompt_tuning":True,
        "source_authenticated_against_original_git_before_inference":True,
        "researcher_operated_not_independent_adoption":True,
        "expert_gold_labels":0,"registered_network_evaluator":False,
        "official_h2_entry_submitted":False,
        "original_github_run":(
            "https://github.com/Iniwura/falsum/actions/runs/"+os.environ["GITHUB_RUN_ID"]
            if "GITHUB_RUN_ID" in os.environ else None),
        "predictions":predictions,
    }


def audit(challenge:dict,references:dict[str,str],raw:dict,model_key:str)->dict:
    require(model_key in MODEL_CHOICES and raw.get("schema_version")==1
            and raw.get("status")==ST_RAW
            and raw.get("model_size_key")==model_key
            and raw.get("original_publisher_model_repo")==MODEL_CHOICES[model_key][0]
            and raw.get("original_immutable_publisher_revision")==MODEL_CHOICES[model_key][1]
            and raw.get("frozen_preinference_git_blob_sha1")==LOCK_SHA1
            and raw.get("challenge_sha256")==sha(canonical_json(challenge))
            and raw.get("actual_model_forward_passes")==24
            and raw.get("original_published_model_loaded") is True
            and raw.get("no_test_labels_given_to_model") is True
            and raw.get("no_model_training_or_prompt_tuning") is True
            and raw.get("source_authenticated_against_original_git_before_inference") is True
            and raw.get("researcher_operated_not_independent_adoption") is True
            and raw.get("expert_gold_labels")==0
            and raw.get("registered_network_evaluator") is False
            and raw.get("official_h2_entry_submitted") is False,
            "model output is not original complete frozen-source inference")
    hashes=raw.get("publisher_model_file_sha256")
    require(isinstance(hashes,dict)
            and hashes.get("model.safetensors")==raw.get("original_model_weight_sha256")
            and "tokenizer.json" in hashes and "config.json" in hashes
            and all(isinstance(x,str) and re.fullmatch(r"[0-9a-f]{64}",x) for x in hashes.values()),
            "immutable published model weight SHA fingerprints incomplete")
    if model_key=="small":
        require(hashes["model.safetensors"]==MODEL_SAFETENSORS_SHA256,
                "original known verified 0.5B model weights mismatch")
    rows=raw.get("predictions")
    require(isinstance(rows,list) and len(rows)==24
            and [x.get("id") for x in rows]==[q["id"] for q in challenge["questions"]],
            "truncated, duplicated or reordered original model predictions")
    for row in rows:
        require(set(row)=={"id","input_tokens","output_tokens","raw_completion","parsed_choice"}
                and type(row["input_tokens"]) is int and
                0<row["input_tokens"]<=1024
                and type(row["output_tokens"]) is int and
                0<row["output_tokens"]<=12
                and isinstance(row["raw_completion"],str)
                and row["parsed_choice"]==parse_choice(row["raw_completion"]),
                "raw model choice parsed incorrectly or fabricated model metadata")
    s=score(references,{x["id"]:x["parsed_choice"] for x in rows},
            origin="RESEARCHER_OPERATED_REAL_PUBLISHED_MODEL")
    return {"schema_version":1,"status":ST_AUDIT,
            "model_repository":MODEL_CHOICES[model_key][0],
            "model_revision":MODEL_CHOICES[model_key][1],
            "model_weight_sha256":hashes["model.safetensors"],
            "original_github_run":raw.get("original_github_run"),
            "exact_challenge_sha256":raw["challenge_sha256"],
            "frozen_protocol_git_blob_sha1":LOCK_SHA1,
            "score":s,
            "original_unmodified_raw_completions":rows,
            "model_predictions_researcher_operated":True,
            "public_known_sources_not_sealed_hidden_holdout":True,
            "no_external_human_gold_or_developer_adoption":True,
            "no_model_training_or_evaluator_registration":True,
            "no_h2_entry_submitted":True,
            "source_blind_proof_scope":"Only prompt-visible input with source code masked, no IDs/source URLs/public repo lookup. Does not defend against a public answer-key lookup.",
            }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Counterbalanced source-revision & answer-slot evaluator (not blind gold)")
    modes=parser.add_subparsers(dest="mode",required=True)
    exp=modes.add_parser("export")
    exp.add_argument("--questions-out",type=Path,required=True)
    exp.add_argument("--template-out",type=Path,required=True)
    sc=modes.add_parser("score")
    sc.add_argument("--questions",type=Path,required=True)
    sc.add_argument("--predictions",type=Path,required=True)
    sc.add_argument("--out",type=Path,required=True)
    bas=modes.add_parser("baseline")
    bas.add_argument("--out",type=Path,required=True)
    inf=modes.add_parser("infer")
    inf.add_argument("--questions",type=Path,required=True)
    inf.add_argument("--out",type=Path,required=True)
    inf.add_argument("--model",choices=tuple(MODEL_CHOICES),required=True)
    aud=modes.add_parser("audit")
    aud.add_argument("--questions",type=Path,required=True)
    aud.add_argument("--raw",type=Path,required=True)
    aud.add_argument("--out",type=Path,required=True)
    aud.add_argument("--model",choices=tuple(MODEL_CHOICES),required=True)
    a=parser.parse_args(argv)
    try:
        challenge,references=build()
        if a.mode=="export":
            require(a.questions_out!=a.template_out
                    and not a.questions_out.exists() and not a.template_out.exists(),
                    "export outputs must be two fresh write-once files")
            write_once(a.questions_out,challenge)
            write_once(a.template_out,response_template(challenge))
            print(json.dumps({"authenticated_original_git_source_files":8,
                "counterbalanced_public_questions":24,"source_blind_four_way_bound":0,
                "independent_expert_gold":0},sort_keys=True))
            return 0
        if a.mode=="baseline":
            result={"status":"PHASE5S_SOURCE_BLIND_LIMITED_PROMPT_ONLY_SYNTHETIC_CONTROL",
                "score":score(references,source_blind_baseline(),
                              origin="DISCLOSED_SYNTHETIC_BASELINE"),
                "source_code_read_by_baseline":False,
                "real_model_inference":False}
        else:
            require(read_json(a.questions.read_bytes())==challenge,
                    "candidate questions do not match authentic original Git source bytes")
            if a.mode=="score":
                selection=validate_responses(challenge,read_json(a.predictions.read_bytes()))
                result={"status":"PHASE5S_EXTERNAL_UNVERIFIED_SUBMISSION_NOT_ADOPTION",
                    "challenge_sha256":sha(canonical_json(challenge)),
                    "outside_developer_independently_verified":False,
                    "score":score(references,selection,
                                  origin="UNVERIFIED_SUBMITTED_CANDIDATE")}
            elif a.mode=="infer":
                result=infer(challenge,a.model)
            else:
                result=audit(challenge,references,read_json(a.raw.read_bytes()),a.model)
        require(not a.out.exists() and not a.out.is_symlink(),
                "report is immutable write-once and must not overwrite past results")
        write_once(a.out,result)
        print(json.dumps({"mode":a.mode,"status":result["status"],
            "model_inference_performed":a.mode=="infer",
            "matches":result.get("score",{}).get("matches_to_public_researcher_references"),
            "complete_four_way_reversals":result.get("score",{}).get(
                "complete_correct_four_way_source_and_position_reversals"),
            "not_independent_appsec_gold":True},sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,AssertionError) as exc:
        parser.exit(1,"PHASE5S FROZEN SOURCE-RESPONSE CONTRACT FAILED CLOSED: "+str(exc)[:280]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
