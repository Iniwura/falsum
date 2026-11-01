"""Actual frozen versus intervention LoRA on THREE never-trained public-source cases.

These hypothetical AI-proposed judgments are NOT independent security accuracy
or an untouched sealed benchmark. Model, source and file hashes are retained.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest
from .phase2u_fresh_transfer import PUBLIC, PRIVATE, canonical, validate
from .real_fix_corpus import load_queue

STATUS="FROZEN_VS_RESEARCH_LORA_THREE_NEW_SOURCE_PROVISIONAL_TRANSFER"
class FreshCompareError(ValueError):
    pass


def verify(public: dict,key: dict,train_manifest: dict) -> list[tuple[dict,dict]]:
    if (not isinstance(public,dict) or not isinstance(key,dict)
            or public.get("status")!=PUBLIC or key.get("status")!=PRIVATE
            or public.get("sealed_holdout") is not False
            or public.get("network_eligible") is not False
            or public.get("training_authorized") is not False
            or public.get("independent_human_reviews")!=0
            or key.get("independent_human_reviews")!=0
            or key.get("training_authorized") is not False
            or key.get("network_eligible") is not False
            or key.get("public_packet_sha256")!=hashlib.sha256(canonical(public)).hexdigest()):
        raise FreshCompareError("fresh unreviewed packet was promoted or manipulated")
    if (train_manifest.get("status")!="AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK"
            or train_manifest.get("network_eligible") is not False
            or train_manifest.get("training_authorized_for_submission") is not False
            or train_manifest.get("independent_human_reviews")!=0
            or train_manifest.get("prior_ai_draft_inspected") is not True):
        raise FreshCompareError("missing quarantined training provenance")
    qs,keys=public.get("cases"),key.get("entries")
    if not isinstance(qs,list) or not isinstance(keys,list) or len(qs)!=6 or len(keys)!=6:
        raise FreshCompareError("six transfer tasks and private choices required")
    groups=defaultdict(list)
    seen=set()
    pairs=[]
    for q,k in zip(qs,keys):
        if not isinstance(q,dict) or set(q)!={"case_id","question","candidate_a","candidate_b"}:
            raise FreshCompareError("model input leaked label or has unexpected fields")
        if q.get("case_id")!=k.get("case_id") or q["case_id"] in seen:
            raise FreshCompareError("wrong candidate / private preference alignment")
        if (k.get("ai_proposed_choice") not in ("A","B")
                or k.get("ai_proposed_kind") not in ("finding","conditional")
                or k.get("human_approved") is not False
                or k.get("independent_ground_truth") is not False
                or k.get("training_eligible") is not False):
            raise FreshCompareError("false reviewer or changed AI proposal")
        if k.get("source_project") in train_manifest["training_projects"]:
            raise FreshCompareError("transfer source included in training; cannot call source-separated")
        if q["candidate_a"]==q["candidate_b"]:
            raise FreshCompareError("duplicate candidate")
        seen.add(q["case_id"])
        groups[k["source_project"]].append((q,k))
        pairs.append((q,k))
    if len(groups)!=3:
        raise FreshCompareError("three distinct new upstream projects required")
    for project,items in groups.items():
        if (len(items)!=2 or
                {x[1]["ai_proposed_kind"] for x in items}!={"finding","conditional"} or
                {items[0][0]["candidate_a"],items[0][0]["candidate_b"]} !=
                {items[1][0]["candidate_a"],items[1][0]["candidate_b"]}):
            raise FreshCompareError("source group lacks exact same candidate essays under opposite contexts")
    return pairs


def evaluate(pairs: list[tuple[dict,dict]], score_function) -> dict:
    cache={}
    rows=[]
    for q,key in pairs:
        def score(prompt,answer):
            item=(prompt,answer)
            if item not in cache:
                value=score_function(prompt,answer)
                if type(value) not in (float,int) or not math.isfinite(value):
                    raise FreshCompareError("invalid model score")
                cache[item]=float(value)
            return cache[item]
        a=score(q["question"],q["candidate_a"])
        b=score(q["question"],q["candidate_b"])
        ab_a=score("",q["candidate_a"])
        ab_b=score("",q["candidate_b"])
        direction=1 if key["ai_proposed_choice"]=="A" else -1
        margin=direction*(a-b)
        rows.append({"case_id":q["case_id"],"project":key["source_project"],
                     "ai_proposed_kind":key["ai_proposed_kind"],
                     "score_a":a,"score_b":b,
                     "margin_to_ai_proposal":margin,
                     "answer_only_margin_to_ai_proposal":direction*(ab_a-ab_b),
                     "agrees_with_ai_proposal":margin>0})
    groups=defaultdict(list)
    for row in rows:
        groups[row["project"]].append(row)
    details={}
    for family,items in groups.items():
        if len(items)!=2 or len({x["ai_proposed_kind"] for x in items})!=2:
            raise FreshCompareError("family split mismatch")
        details[family]={"research_contexts":2,
                         "both_ai_proposals_matched":all(x["agrees_with_ai_proposal"] for x in items),
                         "ai_proposals_matched":sum(x["agrees_with_ai_proposal"] for x in items),
                         "provisional_margins":[x["margin_to_ai_proposal"] for x in items]}
        # Answer-only score of same essay cannot agree with both opposite preferences.
        if all(x["answer_only_margin_to_ai_proposal"]>0 for x in items):
            raise FreshCompareError("answer-only score falsely satisfies both opposite choices")
    return {"actual_inferences":len(cache),
            "ai_proposals_matched":sum(x["agrees_with_ai_proposal"] for x in rows),
            "total_ai_proposals":len(rows),
            "families_matching_both_ai_proposals":sum(x["both_ai_proposals_matched"] for x in details.values()),
            "family_count":len(details),"source_family_details":details,"case_scores":rows}


def compare(public:dict,key:dict,train:dict,baseline_scorer,new_scorer)->dict:
    pairs=verify(public,key,train)
    baseline=evaluate(pairs,baseline_scorer)
    experiment=evaluate(pairs,new_scorer)
    return {"schema_version":1,"status":STATUS,
            "model_actual_training_performed_outside_this_script":True,
            "research_only":True,"source_separated_but_not_sealed":True,
            "independent_security_accuracy_certified":False,
            "network_eligible":False,"registered":False,
            "human_reviews":0,"accepted_evaluation_pairs":0,
            "prior_model":baseline,"context_intervention":experiment,
            "change_in_ai_proposal_agreements":experiment["ai_proposals_matched"]-baseline["ai_proposals_matched"],
            "change_in_families_matching_both":experiment["families_matching_both_ai_proposals"]-baseline["families_matching_both_ai_proposals"],
            "notice":"Three authentic Git source fixes and hypothetical AI-created deployment comparisons, not human ground truth. The training used previously inspected source families. This transfer check has not been used for training, but is public and not a sealed independent benchmark."}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Real unregistered ModernBERT original versus transfer LoRA on three new projects")
    for name in ("public","key","train-manifest","baseline-adapter","experiment-adapter","baseline-decision","baseline-counterfactual","out"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        inputs=[a.public,a.key,a.train_manifest,a.baseline_adapter,a.experiment_adapter,
                a.baseline_decision,a.baseline_counterfactual,a.out]
        if len({x.resolve() for x in inputs})!=8 or a.out.exists():
            raise FreshCompareError("refuse overwritten or aliased model artifacts")
        public=json.loads(a.public.read_text())
        key=json.loads(a.key.read_text())
        train=json.loads(a.train_manifest.read_text())
        _=verify(public,key,train)
        original=adapter_artifact_manifest(a.baseline_adapter)
        newer=adapter_artifact_manifest(a.experiment_adapter)
        decision=json.loads(a.baseline_decision.read_text())
        previous=json.loads(a.baseline_counterfactual.read_text())
        if (decision.get("status")!="BLOCKED_RESEARCH_ONLY"
                or decision.get("adapter_sha256")!=original["sha256"]
                or decision.get("network_eligible") is not False
                or decision.get("registration_authorized") is not False
                or previous.get("adapter_artifact",{}).get("sha256")!=original["sha256"]
                or previous.get("not_network_eligible") is not True
                or original["sha256"]==newer["sha256"]):
            raise FreshCompareError("checkpoint origin, frozen baseline or real new model not verified")
        old_model=ModernBertAdapterScorer(str(a.baseline_adapter))
        new_model=ModernBertAdapterScorer(str(a.experiment_adapter))
        report=compare(public,key,train,old_model,new_model)
        report["prior_adapter_sha256"]=original["sha256"]
        report["new_adapter_sha256"]=newer["sha256"]
        report["public_source_packet_sha256"]=hashlib.sha256(a.public.read_bytes()).hexdigest()
        report["training_provenance_sha256"]=hashlib.sha256(a.train_manifest.read_bytes()).hexdigest()
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":report["status"],"original":report["prior_model"]["ai_proposals_matched"],
                          "new":report["context_intervention"]["ai_proposals_matched"],
                          "baseline_full_families":report["prior_model"]["families_matching_both_ai_proposals"],
                          "new_full_families":report["context_intervention"]["families_matching_both_ai_proposals"],
                          "human_reviews":0,"network_eligible":False},indent=2))
        return 0
    except (FreshCompareError,TypeError,ValueError,KeyError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM NEW PROJECT MODEL TRANSFER ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
