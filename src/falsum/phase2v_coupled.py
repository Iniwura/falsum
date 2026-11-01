"""Phase 2V: paired-context *gradient* intervention on inspected AI-draft projects.

TRAIN ONLY. Four source-authenticated projects were already inspected in 2T
and trained on in 2U. No human labels, no blind benchmark, no network release.
This is not the upstream official trainer; it uses the official pinned
ModernBERT architecture, RenderForJudgment and PEFT adapter as a starting point
and implements an EXPLICIT experimental coupled-context objective.

Loss: softplus(target - delta_exposed) + softplus(target + delta_missing)
 + contrast_weight * softplus(2*target - (delta_exposed-delta_missing))
 + neutral_weight * (delta_answer_only**2).

The final expression punishes dependence on the answer style without question
context, even if the ranker memorizes a generic preferred essay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from pathlib import Path

from .ai_review_model_probe import _verify
from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest, render
from .phase2t_project_isolation import validate_pools
from .phase2t_prior_exposure import audit
from .real_fix_corpus import load_queue

STATUS="EXPERIMENTAL_COUPLED_CONTEXT_MODEL_NOT_CERTIFIED"

class CoupledError(ValueError):
    pass


def build_families(public:dict,key:dict,manifest:dict,train:dict,old:dict,prior:dict)->list[dict]:
    verified=_verify(public,key)
    isolation=validate_pools(train,old)
    exposure=audit(prior,train,old)
    allowed={r["id"] for r in train["cases"]}
    if (not isolation["project_separation_verified"] or
            exposure["pools"][0]["exact_advisory_matches"]!=0 or
            manifest.get("status")!="AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK"
            or manifest.get("training_projects")!=sorted({r["repository"] for r in train["cases"]})
            or manifest.get("independent_human_reviews")!=0
            or manifest.get("network_eligible") is not False
            or manifest.get("prior_ai_draft_inspected") is not True
            or manifest.get("ai_source_packet_sha256") != hashlib.sha256(
                (json.dumps(public,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
            ).hexdigest()
            or manifest.get("ai_proposal_key_sha256") != hashlib.sha256(
                (json.dumps(key,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()
            ).hexdigest()):
        raise CoupledError("wrong or promoted source-training provenance")
    grouped={}
    for q,k in verified:
        if k["source_case"] not in allowed:
            raise CoupledError("context outside source-authenticated train projects")
        grouped.setdefault(k["source_case"],{})[k["proposed_kind"]]=(q,k)
    if len(grouped)!=4 or any(set(v)!={"finding","conditional"} for v in grouped.values()):
        raise CoupledError("four source families must each have opposing contexts")
    result=[]
    for name, cases in sorted(grouped.items()):
        exposed,ex_key=cases["finding"]
        missing,no_key=cases["conditional"]
        chosen=lambda row,key:row["candidate_a"] if key["proposed_preferred"]=="A" else row["candidate_b"]
        finding=chosen(exposed,ex_key)
        conditional=chosen(missing,no_key)
        if finding==conditional or {finding,conditional}!={exposed["candidate_a"],exposed["candidate_b"]}:
            raise CoupledError("identical or wrong-context preferred essays")
        result.append({"id":name,"exposure_prompt":exposed["question"],
                       "missing_prompt":missing["question"],
                       "finding_answer":finding,"conditional_answer":conditional})
    return result


def _numerical_loss(ex_margin, no_margin, no_prompt_margin, *, target:float, contrast_weight:float,
                    neutral_weight:float, softplus):
    """Generic torch or mathematical softplus, so offline tests verify invariants."""
    if not (0<target<=2 and 0<contrast_weight<=5 and 0<=neutral_weight<=2):
        raise CoupledError("loss coefficient outside reviewed experiment range")
    return (softplus(target-ex_margin)
            +softplus(target+no_margin)
            +contrast_weight*softplus(2*target-ex_margin+no_margin)
            +neutral_weight*no_prompt_margin**2)


def _metrics(families:list[dict], score)->dict:
    rows=[]
    for f in families:
        exposed=score(f["exposure_prompt"],f["finding_answer"])-score(f["exposure_prompt"],f["conditional_answer"])
        missing=score(f["missing_prompt"],f["finding_answer"])-score(f["missing_prompt"],f["conditional_answer"])
        ablation=score("",f["finding_answer"])-score("",f["conditional_answer"])
        if any(not math.isfinite(m) for m in (exposed,missing,ablation)):
            raise CoupledError("nonfinite score during context check")
        rows.append({"id":f["id"],"exposure_margin":exposed,"missing_margin":missing,
                     "answer_only_margin":ablation,
                     "both_provisional_contexts_correct":exposed>0 and missing<0})
    return {"groups":len(rows),"matching_both_provisional_contexts":sum(r["both_provisional_contexts_correct"] for r in rows),
            "provisional_cases_matched":sum((r["exposure_margin"]>0)+(r["missing_margin"]<0) for r in rows),
            "case_margins":rows}


def train_coupled(families:list[dict], adapter:Path, out:Path, *,
                  steps:int, lr:float, target:float, contrast_weight:float,
                  neutral_weight:float, seed:int)->dict:
    if type(steps) is not int or not 1<=steps<=48:
        raise CoupledError("training steps must be 1..48")
    if not isinstance(lr,(int,float)) or not 1e-6<=lr<=5e-4:
        raise CoupledError("learning rate outside research safety range")
    if out.exists() or out.resolve()==adapter.resolve():
        raise CoupledError("refuse overwriting trained input adapter")
    if len(families)!=4:
        raise CoupledError("four complete source project reversals required")
    import torch
    from torch.nn import functional as F
    from transformers import AutoConfig,AutoTokenizer,AutoModelForSequenceClassification
    from peft import PeftModel
    from wide_runtime.train_adapter import check_tokenizer
    random.seed(seed);torch.manual_seed(seed)
    base="answerdotai/ModernBERT-base"
    config=AutoConfig.from_pretrained(base)
    if config.model_type.lower()!="modernbert":
        raise CoupledError("unsupported scoring architecture")
    tokenizer=AutoTokenizer.from_pretrained(base)
    check_tokenizer(tokenizer)
    backbone=AutoModelForSequenceClassification.from_pretrained(base,num_labels=1,torch_dtype=torch.float32,
                                                                  attn_implementation="eager")
    model=PeftModel.from_pretrained(backbone,str(adapter),is_trainable=True)
    trainable=[p for p in model.parameters() if p.requires_grad]
    if not trainable:
        raise CoupledError("PEFT adapter had zero trainable LoRA parameters")
    optim=torch.optim.AdamW(trainable,lr=lr,weight_decay=0.01)
    def tokenize(q:str,a:str)->dict:
        tokens=tokenizer(render(q,a),add_special_tokens=True,return_tensors="pt",truncation=False)
        if tokens["input_ids"].shape[-1]>512:
            raise CoupledError("full source-context input exceeds official 512-token cap")
        return {k:v for k,v in tokens.items() if k in ("input_ids","attention_mask")}
    prepared=[]
    for f in families:
        prepared.append({k:tokenize(prompt,answer) for k,prompt,answer in (
            ("ex_find",f["exposure_prompt"],f["finding_answer"]),
            ("ex_cond",f["exposure_prompt"],f["conditional_answer"]),
            ("no_find",f["missing_prompt"],f["finding_answer"]),
            ("no_cond",f["missing_prompt"],f["conditional_answer"]),
            ("abl_find","",f["finding_answer"]),
            ("abl_cond","",f["conditional_answer"]))})
    max_full=max(int(v["input_ids"].shape[-1]) for p in prepared for v in p.values())
    def infer(example):
        return model(**example).logits.float().reshape(-1).squeeze(0)
    def inspect()->dict:
        model.eval()
        with torch.inference_mode():
            scores=[]
            for f,p in zip(families,prepared):
                margins={
                    "id":f["id"],
                    "exposure_margin":(infer(p["ex_find"])-infer(p["ex_cond"])).item(),
                    "missing_margin":(infer(p["no_find"])-infer(p["no_cond"])).item(),
                    "answer_only_margin":(infer(p["abl_find"])-infer(p["abl_cond"])).item()
                }
                scores.append(margins)
        return {"groups":4,
                "matching_both_provisional_contexts":sum(x["exposure_margin"]>0 and x["missing_margin"]<0 for x in scores),
                "provisional_cases_matched":sum((x["exposure_margin"]>0)+(x["missing_margin"]<0) for x in scores),
                "case_margins":scores}
    original=inspect()
    sequence=[i%len(prepared) for i in range(steps)]
    random.Random(seed).shuffle(sequence)
    losses=[]
    for n,i in enumerate(sequence):
        model.train()
        p=prepared[i]
        ex=infer(p["ex_find"])-infer(p["ex_cond"])
        no=infer(p["no_find"])-infer(p["no_cond"])
        neutral=infer(p["abl_find"])-infer(p["abl_cond"])
        loss=_numerical_loss(ex,no,neutral,target=target,contrast_weight=contrast_weight,
                             neutral_weight=neutral_weight,softplus=F.softplus)
        if not torch.isfinite(loss):
            raise CoupledError("non-finite consistency objective")
        optim.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(trainable,max_norm=1.0,error_if_nonfinite=True)
        optim.step()
        losses.append(float(loss.item()))
        print(json.dumps({"step":n+1,"family":families[i]["id"],
                          "objective":round(losses[-1],6)},sort_keys=True),flush=True)
    trained=inspect()
    if not all(math.isfinite(n) for n in losses):
        raise CoupledError("non-finite gradients or losses")
    out.mkdir(parents=True)
    model.save_pretrained(str(out),safe_serialization=True)
    manifest=adapter_artifact_manifest(out)
    return {"schema_version":1,"status":STATUS,
            "training_steps":steps,"learning_rate":lr,"loss_target":target,
            "contrast_weight":contrast_weight,"answer_only_neutral_weight":neutral_weight,
            "seed":seed,"model_backbone":base,
            "full_train_inputs":24,"max_full_model_tokens":max_full,
            "trainable_parameter_count":sum(x.numel() for x in trainable),
            "actual_context_loss_initial":losses[0],
            "actual_context_loss_final":losses[-1],
            "initial_inspected_training_source_metrics":original,
            "posttrain_inspected_training_source_metrics":trained,
            "output_adapter_sha256":manifest["sha256"],
            "research_only":True,"network_eligible":False,"independent_accuracy_measured":False,
            "human_expert_labels":0,"model_submitted":False,
            "warning":"Custom coupled-context gradient training on four already inspected AI-authored project examples. In-sample ranking flips are NOT out-of-sample effectiveness or independent security ground truth."}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Train a real experimental 2-context margin ranker on source-bound AI proposals")
    for field in ("public","key","training-manifest","train-queue","old-queue","prior","adapter","out","report"):
        p.add_argument("--"+field,type=Path,required=True)
    p.add_argument("--steps",type=int,default=16)
    p.add_argument("--lr",type=float,default=0.00012)
    p.add_argument("--target",type=float,default=0.25)
    p.add_argument("--contrast-weight",type=float,default=0.6)
    p.add_argument("--neutral-weight",type=float,default=0.1)
    p.add_argument("--seed",type=int,default=23)
    a=p.parse_args(argv)
    try:
        paths=[a.public,a.key,a.training_manifest,a.train_queue,a.old_queue,a.prior,a.adapter,a.out,a.report]
        if len({x.resolve() for x in paths})!=len(paths) or a.out.exists() or a.report.exists():
            raise CoupledError("input/output aliases or overwrite refused")
        public=json.loads(a.public.read_text())
        key=json.loads(a.key.read_text())
        manifest=json.loads(a.training_manifest.read_text())
        prior=json.loads(a.prior.read_text())
        train,old=load_queue(a.train_queue),load_queue(a.old_queue)
        families=build_families(public,key,manifest,train,old,prior)
        original=adapter_artifact_manifest(a.adapter)
        if original["sha256"]!="a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33":
            raise CoupledError("only the pinned Phase2U actual original adapter may be fine-tuned")
        result=train_coupled(families,a.adapter,a.out,steps=a.steps,lr=a.lr,target=a.target,
                             contrast_weight=a.contrast_weight,neutral_weight=a.neutral_weight,seed=a.seed)
        result["input_phase2u_adapter_sha256"]=original["sha256"]
        result["training_public_packet_sha256"]=hashlib.sha256(a.public.read_bytes()).hexdigest()
        result["training_manifest_sha256"]=hashlib.sha256(a.training_manifest.read_bytes()).hexdigest()
        a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
        print(json.dumps({k:result[k] for k in (
            "status","training_steps","max_full_model_tokens","actual_context_loss_initial",
            "actual_context_loss_final","input_phase2u_adapter_sha256","output_adapter_sha256",
            "human_expert_labels","network_eligible")},indent=2),flush=True)
        return 0
    except (CoupledError,ValueError,KeyError,TypeError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM COUPLED CONTEXT TRAINING ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
