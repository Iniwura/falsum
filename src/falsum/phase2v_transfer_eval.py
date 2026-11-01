"""Run actual Phase2U vs Phase2V adapters on three source-separated AI research cases."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest
from .phase2u_fresh_compare import compare

STATUS="PHASE2V_PAIRED_OBJECTIVE_SOURCE_SEPARATED_DIAGNOSTIC_NOT_SECURITY_ACCURACY"

class TransferEvaluationError(ValueError):
    pass


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Compare actual Phase2V coupled LoRA against source-disjoint Phase2U model")
    for name in ("public","key","train-manifest","old-adapter","new-adapter","new-training-report","out"):
        p.add_argument("--"+name,required=True,type=Path)
    args=p.parse_args(argv)
    try:
        inputs=[args.public,args.key,args.train_manifest,args.old_adapter,args.new_adapter,args.new_training_report,args.out]
        if len({x.resolve() for x in inputs})!=len(inputs) or args.out.exists():
            raise TransferEvaluationError("model paths collide or report would overwrite evidence")
        pub=json.loads(args.public.read_text())
        key=json.loads(args.key.read_text())
        train=json.loads(args.train_manifest.read_text())
        new_training=json.loads(args.new_training_report.read_text())
        old=adapter_artifact_manifest(args.old_adapter)
        new=adapter_artifact_manifest(args.new_adapter)
        if (old["sha256"]!="a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33"
                or old["sha256"]==new["sha256"]
                or new_training.get("status")!="EXPERIMENTAL_COUPLED_CONTEXT_MODEL_NOT_CERTIFIED"
                or new_training.get("input_phase2u_adapter_sha256")!=old["sha256"]
                or new_training.get("output_adapter_sha256")!=new["sha256"]
                or new_training.get("human_expert_labels")!=0
                or new_training.get("network_eligible") is not False):
            raise TransferEvaluationError("model provenance, real gradient intervention or quarantine failed")
        baseline=ModernBertAdapterScorer(str(args.old_adapter))
        treatment=ModernBertAdapterScorer(str(args.new_adapter))
        report=compare(pub,key,train,baseline,treatment)
        report["status"]=STATUS
        report["control_phase2u_adapter_sha256"]=old["sha256"]
        report["treatment_phase2v_adapter_sha256"]=new["sha256"]
        report["treatment_training_report_sha256"]=hashlib.sha256(args.new_training_report.read_bytes()).hexdigest()
        report["model_training_objective"]="coupled contrastive true opposite deployment contexts + answer-only zero-margin penalty"
        report["train_projects_previous_inspected"]=True
        report["evaluation_projects_not_in_phase2v_train"]=True
        report["source_project_separated_but_not_sealed"]=True
        report["eligible_Anjoman_evaluation_rows"]=0
        report["registered_live_evaluator"]=False
        report["independent_security_accuracy_certified"]=False
        report["network_eligible"]=False
        report["notice"]="Three public original source projects, untrained in Phase2V; labels and deployment facts are AI-authored. This is a development diagnostic, not independent expert accuracy or network readiness."
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({"status":report["status"],
                          "phase2u_ai_proposal_agreement":report["prior_model"]["ai_proposals_matched"],
                          "phase2v_ai_proposal_agreement":report["context_intervention"]["ai_proposals_matched"],
                          "phase2u_full_context_families":report["prior_model"]["families_matching_both_ai_proposals"],
                          "phase2v_full_context_families":report["context_intervention"]["families_matching_both_ai_proposals"],
                          "human_reviews":0,"network_eligible":False},indent=2))
        return 0
    except (TransferEvaluationError,ValueError,KeyError,TypeError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM COUPLED SOURCE TRANSFER EVALUATION ERROR: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
