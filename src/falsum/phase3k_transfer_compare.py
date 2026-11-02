"""Phase 3K: real old-vs-intervention adapter scoring on separated but SEEN public projects.

Tornado, Undici, websockets were never used in the proposed Phase 3K
intervention, but were already inspected/scored in prior FALSUM phases.
They cannot be called a clean blind holdout or independent ground truth.
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
from pathlib import Path

from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest
from .phase2u_fresh_compare import verify, evaluate
from .phase3k_intervention import STATUS as TRAIN_STATUS, SOURCE_PROJECTS, TRANSFER_EXCLUDED


class Phase3KCompareError(ValueError):
    pass


def assess(public:dict,private:dict,old_train:dict,new_train:dict,
           old_scores:dict,new_scores:dict,old_artifact:dict,new_artifact:dict)->dict:
    pairs=verify(public,private,old_train)
    if (not isinstance(new_train,dict) or new_train.get("status")!=TRAIN_STATUS
        or new_train.get("known_runtime_context_training_pairs")!=8
        or new_train.get("balanced_reversal_families")!=2
        or new_train.get("seen_training_projects")!=list(SOURCE_PROJECTS)
        or new_train.get("already_inspected_transfer_projects_excluded")!=list(TRANSFER_EXCLUDED)
        or new_train.get("independent_human_approved_labels")!=0
        or new_train.get("training_or_labels_authorized_for_submittable_network_module") is not False
        or new_train.get("network_eligible") is not False):
        raise Phase3KCompareError("unverified source-project or research-only intervention")
    projects={k["source_project"] for _,k in pairs}
    if projects!=set(TRANSFER_EXCLUDED) or projects&set(new_train["seen_training_projects"]):
        raise Phase3KCompareError("previously inspected transfer project overlaps intervention training")
    if not isinstance(old_scores,dict) or not isinstance(new_scores,dict):
        raise Phase3KCompareError("missing real model score reports")
    if old_scores.get("family_count")!=3 or new_scores.get("family_count")!=3:
        raise Phase3KCompareError("three source-separated family comparisons required")
    if old_scores.get("total_ai_proposals")!=6 or new_scores.get("total_ai_proposals")!=6:
        raise Phase3KCompareError("six source-dependent provisional preferences required")
    if (not isinstance(old_artifact,dict) or not isinstance(new_artifact,dict)
        or old_artifact.get("sha256")==new_artifact.get("sha256")
        or not old_artifact.get("sha256") or not new_artifact.get("sha256")):
        raise Phase3KCompareError("new adapter is unchanged or missing")
    before=old_scores["ai_proposals_matched"]
    after=new_scores["ai_proposals_matched"]
    return {
        "schema_version":1,
        "status":"PHASE3K_ACTUAL_NEW_VS_PRIOR_LORA_PREVIOUSLY_INSPECTED_TRANSFER_RESEARCH_ONLY",
        "intent":"SECURITY_REVIEW_GENERAL",
        "before_adapter_manifest_sha256":old_artifact["sha256"],
        "after_adapter_manifest_sha256":new_artifact["sha256"],
        "research_training_manifest_sha256":hashlib.sha256(
            json.dumps(new_train,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        ).hexdigest(),
        "transfer_source_projects":sorted(projects),
        "not_trained_on_any_transfer_project":True,
        "source_separated_but_previous_models_inspected_this_comparison":True,
        "preference_label_origin":"FALSUM_AI_PROVISIONAL_NOT_HUMAN_VERIFIED",
        "before":old_scores,"after":new_scores,
        "before_ai_provisional_contexts_matched":before,
        "after_ai_provisional_contexts_matched":after,
        "observed_delta_context_matches":after-before,
        "before_complete_reversals":old_scores["families_matching_both_ai_proposals"],
        "after_complete_reversals":new_scores["families_matching_both_ai_proposals"],
        "before_model_foundation_scored_with_official_wasi":False,
        "new_model_foundation_scored_with_official_wasi":False,
        "model_accuracy_independently_certified":False,
        "human_approved_labels":0,"accepted_anjoman_rows":0,
        "registered_evaluator":False,"network_eligible":False,
        "original_release_veto_still_applies":True,
        "notice":"Scores from two real HF/PyTorch installed LoRA checkpoints, not exported official WASI scoring. They compare already-seen public provisional transfer questions, not independent blind security accuracy. Positive or negative delta never authorizes model release."
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Actual original vs Phase3K research LoRA; no release")
    for name in ("public","private","old-train-manifest","new-train-manifest","before-adapter","after-adapter","out"):
        parser.add_argument("--"+name,required=True,type=Path)
    a=parser.parse_args(argv)
    try:
        if a.out.exists():
            raise Phase3KCompareError("refuse overwriting prior model diagnostics")
        public=json.loads(a.public.read_text())
        key=json.loads(a.private.read_text())
        original=json.loads(a.old_train_manifest.read_text())
        new=json.loads(a.new_train_manifest.read_text())
        pairs=verify(public,key,original)
        old_meta=adapter_artifact_manifest(a.before_adapter)
        new_meta=adapter_artifact_manifest(a.after_adapter)
        baseline=ModernBertAdapterScorer(str(a.before_adapter))
        old_scores=evaluate(pairs,baseline)
        del baseline
        gc.collect()
        intervention=ModernBertAdapterScorer(str(a.after_adapter))
        new_scores=evaluate(pairs,intervention)
        del intervention
        gc.collect()
        report=assess(public,key,original,new,old_scores,new_scores,old_meta,new_meta)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps({
            "status":report["status"],"before_context_matches":report["before_ai_provisional_contexts_matched"],
            "after_context_matches":report["after_ai_provisional_contexts_matched"],
            "before_full_reversals":report["before_complete_reversals"],
            "after_full_reversals":report["after_complete_reversals"],
            "blind_accuracy":False,"network_eligible":False
        },indent=2))
        return 0
    except (Phase3KCompareError,ValueError,OSError,TypeError,KeyError,ImportError) as exc:
        parser.exit(1,f"FALSUM PHASE3K REAL TRANSFER COMPARE FAILED: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
