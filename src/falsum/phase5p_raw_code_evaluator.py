"""Authenticated raw-code security-review material, not a learned evaluator or expert gold.

Two real historical versions of each of four previously selected upstream source
files are fetched at pinned commits, verified by their Git blob SHA-1, and only
then excerpted. The model sees actual source, never the researcher's prior
behavioral summary. The prompt and model policy were frozen in an earlier commit.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import time
from urllib.request import Request, urlopen

from .phase4h_frozen_source import validate_lock
from .phase5l_pymdown_upstream_replay import git_blob
from .phase5m_real_source_sensitive_model import ROOT, require, DiagnosticError, read_json, canonical_json, sha
from .phase5n_published_candidate_runner import (
    MODEL_REPO, WHITELIST, MODEL_REPO as QWEN_REPO,
    get_sha256_file, parse_choice, write_once,
)
from .phase5o_four_project_published_model import MODEL_REVISION, MODEL_SAFETENSORS_SHA256

PROTOCOL="data/phase5p-raw-code-preinference-protocol.json"
PROTOCOL_BLOB="a4eae5fd74be73e99f255d8f45da319c928aea48"
SOURCE_LOCK="data/phase4h-frozen-four-new-source-projects.json"
SOURCE_BLOB="9fc67edec49c33d3efdb4a6128bd7c6c6b7766e2"
PROJECTS=("pyjwt","werkzeug","mcp-python","pillow")
CONDITIONS=("code-a","code-b","source-omitted")
LABELS=("A","B","ABSTAIN")
ST_PREP="PHASE5P_AUTHENTIC_GIT_BLOB_RAW_CODE_OPEN_BOOK_CHALLENGE"
ST_TEMPLATE="PHASE5P_UNVERIFIED_DEVELOPER_PREDICTIONS_UNFILLED"
ST_RAW="PHASE5P_REAL_RESEARCHER_OPERATED_QWEN_RAW_CODE_FORWARD_PASSES"
ST_REPORT="PHASE5P_ORIGINAL_RAW_CODE_MODEL_DIAGNOSTIC_NOT_BLIND_GOLD"


def frozen(root:Path=ROOT)->tuple[dict,dict]:
    raw=(root/PROTOCOL).read_bytes()
    require(git_blob(raw)==PROTOCOL_BLOB,"pre-inference raw-code protocol changed")
    p=read_json(raw)
    source_bytes=(root/SOURCE_LOCK).read_bytes()
    require(git_blob(source_bytes)==SOURCE_BLOB,
            "authenticated historical source selection changed")
    source=validate_lock(source_bytes)
    require(p.get("status") ==
            "PHASE5P_SOURCE_SELECTION_AND_EXACT_RAW_CODE_PROMPTS_FROZEN_BEFORE_ANY_MODEL_INFERENCE"
            and p.get("source_lock_git_blob_sha1")==SOURCE_BLOB
            and p.get("programmatic_excerpts_instead_of_model_summaries") is True
            and p.get("total_tasks")==12
            and p.get("project_count")==4
            and p.get("class_balance")=={"A":4,"B":4,"ABSTAIN":4}
            and p.get("conditions_per_project")==list(CONDITIONS)
            and p.get("original_model_baseline")==
                MODEL_REPO+"@"+MODEL_REVISION
            and p.get("model_system_instruction","").endswith("No explanation.")
            and p.get("generation_max_new_tokens")==12
            and p.get("max_input_tokens")==1024
            and p.get("greedy_decode_only") is True
            and p.get("no_few_shot_examples") is True
            and p.get("no_independent_human_expert_gold") is True
            and p.get("no_registered_telegraph_evaluator") is True
            and p.get("no_external_developer_adoption") is True
            and p.get("no_anjoman_eligible_rows") is True
            and p.get("no_official_h2_entry_submitted") is True,
            "raw source benchmark protocol drifted or inflated")
    specs=p.get("project_specs")
    require(isinstance(specs,list) and len(specs)==4
            and tuple(x.get("key") for x in specs)==PROJECTS
            and tuple(x["key"] for x in source["cases"])==PROJECTS,
            "frozen four original project identities changed")
    for spec in specs:
        require(isinstance(spec.get("question"),str) and 75<len(spec["question"])<400
                and all(isinstance(spec.get(k),str) and spec[k] for k in
                        ("parent_anchor","fixed_anchor"))
                and all(isinstance(spec.get(k),list) and len(spec[k])==2
                        and all(type(y) is int and -40<=y<=40 for y in spec[k])
                        for k in ("parent_window","fixed_window")),
                "invalid frozen source question or code excerpt specification")
    return p,source


def ident(project:str,condition:str)->str:
    return hashlib.sha256(("falsum/phase5p/raw-original/"+project+"/"+condition).encode()).hexdigest()[:32]


def _get_source(url:str)->bytes:
    require(url.startswith("https://raw.githubusercontent.com/") and ".." not in url,
            "only exact pinned original GitHub raw sources allowed")
    last=None
    for attempt in range(3):
        try:
            req=Request(url,headers={"User-Agent":"falsum-phase5p-pinned-source-verifier"})
            with urlopen(req,timeout=35) as response:
                require(response.status==200,"pinned source download not HTTP 200")
                raw=response.read(350_000+1)
            require(0<len(raw)<350_000,"missing or oversized public source")
            return raw
        except (OSError,TimeoutError) as exc:
            last=exc
            if attempt<2:
                time.sleep(attempt+1)
    raise DiagnosticError("source file not fetched: "+str(last)[:100])


def _source_for(case:dict,revision:str,downloader=_get_source)->tuple[str,str]:
    require(revision in ("parent","fixed"),"invalid source version")
    repo=case["repository"]
    require(repo in {
        "jpadilla/pyjwt","pallets/werkzeug",
        "modelcontextprotocol/python-sdk","python-pillow/Pillow",
    },"source repository not in original 4H allowlist")
    commit=case[revision]
    require(re.fullmatch(r"[0-9a-f]{40}",commit) is not None,
            "untrusted unpinned source revision")
    source_path=case["source_path"]
    require(".." not in source_path and not source_path.startswith("/"),
            "untrusted source path")
    url="https://raw.githubusercontent.com/"+repo+"/"+commit+"/"+source_path
    raw=downloader(url)
    require(git_blob(raw)==case[revision+"_source_blob"],
            "original upstream Git blob SHA does not match frozen reference")
    return raw.decode("utf-8","strict"),url


def excerpt(text:str,anchor:str,window:list[int],*,
            extra_anchor:str|None=None,extra_window:list[int]|None=None)->str:
    lines=text.splitlines()
    hits=[i for i,line in enumerate(lines) if anchor in line]
    require(len(hits)==1,"source excerpt anchor absent or ambiguous")
    def segment(position:int,span:list[int])->str:
        lo=max(0,position+span[0])
        hi=min(len(lines),position+span[1]+1)
        require(hi>lo and hi-lo<=65,"invalid source excerpt width")
        return "\n".join(lines[lo:hi])
    parts=[segment(hits[0],window)]
    if extra_anchor is not None:
        extras=[i for i,line in enumerate(lines) if extra_anchor in line]
        require(len(extras)==1 and extra_window is not None,
                "independent source function excerpt missing")
        parts.insert(0,segment(extras[0],extra_window))
    code="\n\n# Additional code from the same authenticated source file:\n\n".join(parts)
    require(40<len(code)<9000 and anchor in code,
            "actual code excerpt absent or too large")
    return code


def _render(p:dict,question:str,code:str,a:str,b:str)->str:
    pattern=p["model_user_template"].replace("\\n","\n")
    out=pattern.replace("{question}",question).replace("{code}",code)
    out=out.replace("{answer_a}",a).replace("{answer_b}",b)
    require(len(out)<12500 and "{code}" not in out
            and "{question}" not in out,"prompt substitution failed")
    return out


def build(*,root:Path=ROOT,downloader=_get_source)->tuple[dict,dict[str,str]]:
    p,source=frozen(root)
    rows=[]
    answers={}
    for index,(spec,case) in enumerate(zip(p["project_specs"],source["cases"])):
        require(spec["key"]==case["key"],"source task and case key mismatch")
        swapped=index%2==1
        a=case["b"] if swapped else case["a"]
        b=case["a"] if swapped else case["b"]
        actual={}
        for cond,revision in (("code-a","parent"),("code-b","fixed")):
            whole,url=_source_for(case,revision,downloader)
            prefix="parent" if revision=="parent" else "fixed"
            code=excerpt(
                whole,spec[prefix+"_anchor"],spec[prefix+"_window"],
                extra_anchor=spec.get(prefix+"_extra_anchor"),
                extra_window=spec.get(prefix+"_extra_window"),
            )
            # Avoid smuggling version role into the prompt; a source
            # excerpt may include terms in upstream comments, but no
            # researcher-added parent/fixed/patch guidance.
            actual[cond]=(code,url,case[revision])
        for cond in CONDITIONS:
            key=ident(case["key"],cond)
            if cond=="source-omitted":
                code="[SOURCE FILE OMITTED: no revision or implementation is provided]"
                git_url=None
                commit=None
                answers[key]="ABSTAIN"
            else:
                code,url,commit=actual[cond]
                git_url=url
                intended="A" if cond=="code-a" else "B"
                answers[key]=((
                    "B" if intended=="A" else "A"
                ) if swapped else intended)
            user=_render(p,spec["question"],code,a,b)
            rows.append({
                "id":key,"project":spec["key"],
                "source_git_commit":commit,
                "source_code_url":git_url,
                "source_excerpt":code,
                "source_excerpt_sha256":sha(code.encode()),
                "messages":[
                    {"role":"system","content":p["model_system_instruction"]},
                    {"role":"user","content":user},
                ],
                "prompt_sha256":sha(user.encode()),
            })
    require(len(rows)==12 and len({x["id"] for x in rows})==12
            and Counter(answers.values())=={"A":4,"B":4,"ABSTAIN":4}
            and sum(x["source_git_commit"] is None for x in rows)==4,
            "raw-code challenge balance or complete source revisions failed")
    # Deliberately deterministic challenge order. Explicit source URLs and
    # public generator mean this is NOT a blind or secret score.
    rows.sort(key=lambda q:hashlib.sha256(
        ("falsum/phase5p/public-mix/"+q["id"]).encode()).hexdigest())
    return ({
        "schema_version":1,"status":ST_PREP,
        "intent":"SECURITY_REVIEW_GENERAL",
        "source_lock_git_blob_sha1":SOURCE_BLOB,
        "frozen_protocol_git_blob_sha1":PROTOCOL_BLOB,
        "projects":list(PROJECTS),
        "question_count":12,
        "source_provided_conditions":8,
        "source_omitted_controls":4,
        "answer_key_included":False,
        "reference_is_public_researcher_derived":True,
        "source_files_downloaded_git_blob_verified":True,
        "actual_raw_code_not_researcher_summary":True,
        "historical_source_fixes_public_not_blind":True,
        "independent_appsec_gold":0,
        "network_evaluator_registered":False,
        "external_developer_adoption":False,
        "official_h2_entry_submitted":False,
        "questions":rows,
    },answers)


def response_template(challenge:dict)->dict:
    return {
        "schema_version":1,"status":ST_TEMPLATE,
        "challenge_sha256":sha(canonical_json(challenge)),
        "decisions":[{"id":row["id"],"choice":None}
                     for row in challenge["questions"]],
    }


def validate_responses(challenge:dict,submitted:dict)->dict[str,str]:
    require(isinstance(submitted,dict)
            and set(submitted)=={"schema_version","status","challenge_sha256","decisions"}
            and type(submitted["schema_version"]) is int
            and submitted["schema_version"]==1
            and submitted["status"]==ST_TEMPLATE
            and submitted["challenge_sha256"]==sha(canonical_json(challenge)),
            "candidate response does not match exact original source exercise")
    rows=submitted["decisions"]
    require(isinstance(rows,list) and len(rows)==12,
            "twelve candidate predictions required")
    out={}
    for expected,entry in zip(challenge["questions"],rows):
        require(isinstance(entry,dict)
                and set(entry)=={"id","choice"}
                and entry["id"]==expected["id"]
                and entry["choice"] in LABELS,
                "unknown, reordered, incomplete or extra candidate decision")
        out[entry["id"]]=entry["choice"]
    require(len(out)==12,"duplicate response identifiers")
    return out


def score(answers:dict[str,str],predictions:dict[str,str],*,origin:str)->dict:
    require(origin in ("RESEARCHER_OPERATED_PINNED_PUBLISHED_QWEN",
                       "UNVERIFIED_EXTERNAL_RESPONSES",
                       "DISCLOSED_SYNTHETIC_BASELINE"),
            "forged external review provenance")
    require(set(answers)==set(predictions) and len(answers)==12
            and all(x in LABELS for x in answers.values())
            and all(x in LABELS+("INVALID",) for x in predictions.values()),
            "invalid source prediction set")
    matrix={t:{q:0 for q in LABELS+("INVALID",)} for t in LABELS}
    for key in answers:
        matrix[answers[key]][predictions[key]]+=1
    by_project={}
    reversals=0
    abstentions=0
    for project in PROJECTS:
        ids=[ident(project,c) for c in CONDITIONS]
        a,b,o=(predictions[x] for x in ids)
        passed=a==answers[ids[0]] and b==answers[ids[1]]
        reversals+=int(passed)
        abstentions+=int(o=="ABSTAIN")
        by_project[project]={
            "code_a_choice":a,"code_b_choice":b,
            "source_omitted_choice":o,
            "complete_correct_source_reversal":passed,
            "source_omitted_abstained":o=="ABSTAIN",
        }
    exact=sum(matrix[k][k] for k in LABELS)
    return {
        "schema_version":1,"origin":origin,"intent":"SECURITY_REVIEW_GENERAL",
        "total_questions":12,"authenticated_source_projects":4,
        "source_code_present_questions":8,"source_omitted_controls":4,
        "reference_distribution":{"A":4,"B":4,"ABSTAIN":4},
        "matrix_true_rows_prediction_columns":matrix,
        "matches_to_public_researcher_references":exact,
        "macro_class_recall":round(sum(matrix[k][k]/4 for k in LABELS)/3,6),
        "complete_correct_parent_fix_reversals":reversals,
        "correct_source_omitted_abstentions":abstentions,
        "unnecessary_abstention_with_code_present":
            matrix["A"]["ABSTAIN"]+matrix["B"]["ABSTAIN"],
        "unsupported_confident_answers_no_source":
            matrix["ABSTAIN"]["A"]+matrix["ABSTAIN"]["B"],
        "invalid_model_replies":sum(matrix[k]["INVALID"] for k in LABELS),
        "project_details":by_project,
        "always_abstain_baseline_matches":4,
        "always_A_baseline_matches":4,
        "always_B_baseline_matches":4,
        "source_blind_same_answer_for_all_code_and_abstain_no_source_baseline_matches":8,
        "real_independent_human_expert_gold":0,
        "statistical_model_accuracy_claim":False,
        "new_telegraph_network_ranking":False,
        "trained_model_improvement_proven":False,
        "registered_evaluator":False,
        "official_h2_entry_submitted":False,
    }


def score_external(challenge:dict,answers:dict[str,str],response:dict)->dict:
    selected=validate_responses(challenge,response)
    return {
        "schema_version":1,"status":"PHASE5P_PUBLIC_RAW_CODE_EXTERNAL_PREDICTIONS_NOT_VALIDATED_ADOPTION",
        "challenge_sha256":sha(canonical_json(challenge)),
        "source_git_blob_verified_by_challenge_generator":True,
        "candidate_identity_independently_verified":False,
        "independent_developer_adoption_not_established":True,
        "results":score(answers,selected,origin="UNVERIFIED_EXTERNAL_RESPONSES"),
    }


def infer(prepared:dict)->dict:
    """Actual immutable real model run. No synthetic inference fallback."""
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoTokenizer,AutoModelForCausalLM
    p,_=frozen()
    location=Path(snapshot_download(
        repo_id=QWEN_REPO,revision=MODEL_REVISION,
        allow_patterns=list(WHITELIST),max_workers=2))
    fingerprints={}
    for file in sorted(location.iterdir()):
        if file.is_file() and (file.name in (
            "config.json","generation_config.json","tokenizer.json",
            "tokenizer_config.json","special_tokens_map.json","vocab.json",
            "merges.txt","model.safetensors","model.safetensors.index.json",
        ) or re.fullmatch(r"model-[0-9]+-of-[0-9]+\.safetensors",file.name)):
            fingerprints[file.name]=get_sha256_file(file)
    require(fingerprints.get("model.safetensors")==MODEL_SAFETENSORS_SHA256
            and "tokenizer.json" in fingerprints and "config.json" in fingerprints,
            "actual preverified model weight checkpoint differs")
    torch.set_num_threads(2)
    model=AutoModelForCausalLM.from_pretrained(
        str(location),local_files_only=True,trust_remote_code=False,
        use_safetensors=True,torch_dtype=torch.float32).eval()
    tokenizer=AutoTokenizer.from_pretrained(
        str(location),local_files_only=True,trust_remote_code=False)
    raw=[]
    for item in prepared["questions"]:
        tokens=tokenizer.apply_chat_template(item["messages"],
            add_generation_prompt=True,return_tensors="pt")
        n=int(tokens.shape[-1])
        require(0<n<=p["max_input_tokens"],
                "authenticated raw source truncated by model token limit")
        with torch.inference_mode():
            prediction=model.generate(tokens,max_new_tokens=p["generation_max_new_tokens"],
                                      do_sample=False,pad_token_id=tokenizer.eos_token_id)
        generated=prediction[0,tokens.shape[-1]:]
        answer=tokenizer.decode(generated,skip_special_tokens=True)
        raw.append({"id":item["id"],"raw_completion":answer,
                    "parsed_choice":parse_choice(answer),"input_tokens":n,
                    "output_tokens":int(generated.numel())})
    require(len(raw)==12,"real model did not process every source task")
    return {
        "schema_version":1,"status":ST_RAW,
        "model_repository":MODEL_REPO,"model_revision":MODEL_REVISION,
        "published_model_sha256_files":fingerprints,
        "frozen_protocol_git_blob_sha1":PROTOCOL_BLOB,
        "challenge_sha256":sha(canonical_json(prepared)),
        "actual_cpu_forward_passes":12,
        "real_pretrained_weights_loaded":True,
        "source_labels_not_supplied_to_model":True,
        "source_code_git_blob_verified_prior_to_model":True,
        "researcher_operated_not_independent_adoption":True,
        "network_registered_evaluator":False,
        "qualified_security_expert_labels":0,
        "no_model_training_or_prompt_tuning":True,
        "official_h2_entry_submitted":False,
        "github_run_url":(
            "https://github.com/Iniwura/falsum/actions/runs/"+os.environ["GITHUB_RUN_ID"]
            if "GITHUB_RUN_ID" in os.environ else None),
        "predictions":raw,
    }


def audit(prepared:dict,answer_key:dict[str,str],run:dict)->dict:
    require(isinstance(run,dict) and run.get("schema_version")==1
            and run.get("status")==ST_RAW
            and run.get("model_repository")==MODEL_REPO
            and run.get("model_revision")==MODEL_REVISION
            and run.get("frozen_protocol_git_blob_sha1")==PROTOCOL_BLOB
            and run.get("challenge_sha256")==sha(canonical_json(prepared))
            and run.get("actual_cpu_forward_passes")==12
            and run.get("real_pretrained_weights_loaded") is True
            and run.get("source_labels_not_supplied_to_model") is True
            and run.get("source_code_git_blob_verified_prior_to_model") is True
            and run.get("researcher_operated_not_independent_adoption") is True
            and run.get("network_registered_evaluator") is False
            and run.get("qualified_security_expert_labels")==0
            and run.get("no_model_training_or_prompt_tuning") is True
            and run.get("official_h2_entry_submitted") is False,
            "raw model record does not match frozen real-source protocol")
    files=run.get("published_model_sha256_files")
    require(isinstance(files,dict)
            and files.get("model.safetensors")==MODEL_SAFETENSORS_SHA256
            and all(re.fullmatch(r"[a-f0-9]{64}",v) for v in files.values())
            and len(files)>=3,"real model artifact identity incomplete")
    records=run.get("predictions")
    require(isinstance(records,list) and len(records)==12
            and [x.get("id") for x in records]==[x["id"] for x in prepared["questions"]],
            "wrong real-source question order or count")
    for item in records:
        require(set(item)=={"id","raw_completion","parsed_choice","input_tokens","output_tokens"}
                and isinstance(item["raw_completion"],str)
                and item["parsed_choice"]==parse_choice(item["raw_completion"])
                and type(item["input_tokens"]) is int
                and 0<item["input_tokens"]<=1024
                and type(item["output_tokens"]) is int
                and 0<item["output_tokens"]<=12,
                "invalid model completion or token provenance")
    predictions={x["id"]:x["parsed_choice"] for x in records}
    return {
        "schema_version":1,"status":ST_REPORT,
        "original_real_model_run":run.get("github_run_url"),
        "model_repo":MODEL_REPO,"model_revision":MODEL_REVISION,
        "model_weights_sha256":MODEL_SAFETENSORS_SHA256,
        "challenge_sha256":sha(canonical_json(prepared)),
        "frozen_protocol_git_blob_sha1":PROTOCOL_BLOB,
        "scored":score(answer_key,predictions,
                       origin="RESEARCHER_OPERATED_PINNED_PUBLISHED_QWEN"),
        "original_raw_completions":records,
        "model_run_real_claim_requires_public_actions_and_raw_archive":True,
        "independent_expert_gold":0,
        "adopted_by_external_developer":False,
        "trained_falsum_model_improvement":False,
        "official_telegraph_evaluator_registered":False,
        "new_anjoman_eligible_rows":0,
        "h2_entry_submitted":False,
        "limitations":"Public previously examined original upstream source excerpts, not sealed holdout; answer references are author-derived from upstream historical source and tests, not independent expert gold. Syntactic or metadata shortcuts remain possible. Publisher weights are independently authored but this inference is researcher-operated.",
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Authenticated source-code evaluation material and actual model diagnostic")
    modes=parser.add_subparsers(dest="mode",required=True)
    exp=modes.add_parser("export")
    exp.add_argument("--questions-out",type=Path,required=True)
    exp.add_argument("--template-out",type=Path,required=True)
    sc=modes.add_parser("score")
    sc.add_argument("--questions",type=Path,required=True)
    sc.add_argument("--predictions",type=Path,required=True)
    sc.add_argument("--out",type=Path,required=True)
    inf=modes.add_parser("infer")
    inf.add_argument("--questions",type=Path,required=True)
    inf.add_argument("--out",type=Path,required=True)
    aud=modes.add_parser("audit")
    aud.add_argument("--questions",type=Path,required=True)
    aud.add_argument("--raw",type=Path,required=True)
    aud.add_argument("--out",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        challenge,refs=build()
        if args.mode=="export":
            require(args.questions_out!=args.template_out
                    and not args.questions_out.exists()
                    and not args.template_out.exists(),
                    "export files must be distinct write-once outputs")
            write_once(args.questions_out,challenge)
            write_once(args.template_out,response_template(challenge))
            print(json.dumps({"verified_original_source_files":8,
                              "public_raw_code_questions":12,
                              "independent_expert_gold":0,"model_inference":False},
                             sort_keys=True))
            return 0
        existing=read_json(args.questions.read_bytes())
        require(existing==challenge,
                "source challenge differs from exact original pinned primary sources")
        require(not args.out.exists(),"never overwrite prior predictions or score")
        if args.mode=="score":
            result=score_external(challenge,refs,read_json(args.predictions.read_bytes()))
        elif args.mode=="infer":
            result=infer(challenge)
        else:
            result=audit(challenge,refs,read_json(args.raw.read_bytes()))
        write_once(args.out,result)
        print(json.dumps({
            "mode":args.mode,
            "real_model_inference_performed":args.mode=="infer",
            "score":(result.get("scored") or result.get("results") or {}).get(
                "matches_to_public_researcher_references"),
            "not_independent_expert_gold":True,
        },sort_keys=True))
        return 0
    except (DiagnosticError,OSError,ValueError,KeyError,TypeError,UnicodeError) as exc:
        parser.exit(1,"PHASE5P AUTHENTIC RAW CODE CHALLENGE FAILED CLOSED: "
                    +str(exc)[:280]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
