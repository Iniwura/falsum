"""Research-only comparison of an experimental checkpoint against inspected AI drafts.

A successful numerical preference on an inspected case is not independent
model quality. Absolutely no registration/export/eligibility claim is allowed.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .ai_review_model_probe import evaluate, _verify
from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest

class ComparisonError(ValueError):
    pass

def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Score actual experimental LoRA on previously inspected AI drafts")
    p.add_argument("--public",type=Path,required=True)
    p.add_argument("--key",type=Path,required=True)
    p.add_argument("--adapter",type=Path,required=True)
    p.add_argument("--training-manifest",type=Path,required=True)
    p.add_argument("--report",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.report.exists() or args.report.resolve() in {args.public.resolve(),args.key.resolve(),args.training_manifest.resolve()}:
            raise ComparisonError("cannot overwrite research evidence")
        public=json.loads(args.public.read_text(encoding="utf-8"))
        key=json.loads(args.key.read_text(encoding="utf-8"))
        train=json.loads(args.training_manifest.read_text(encoding="utf-8"))
        _verify(public,key)
        if (train.get("status")!="AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK"
                or train.get("research_only") is not True
                or train.get("prior_ai_draft_inspected") is not True
                or train.get("network_eligible") is not False
                or train.get("independent_human_reviews")!=0):
            raise ComparisonError("wrong model provenance or model-release shortcut")
        test_projects={e["source_repository"] for e in key["entries"]}
        train_projects=set(train["training_projects"])
        if test_projects & train_projects:
            raise ComparisonError("model inspected comparison overlaps the new intervention's source projects")
        original={"ai_proposals_compared":8,"model_agrees_with_ai_proposals":4,
                  "families_matching_both_ai_proposals":0}
        manifest=adapter_artifact_manifest(args.adapter)
        scorer=ModernBertAdapterScorer(str(args.adapter))
        report=evaluate(public,key,scorer)
        report["status"]="PHASE2U_INSPECTED_COMPARISON_NOT_GENERALIZATION"
        report["prior_frozen_model_reference"]=original
        report["new_context_intervention_train_projects"]=sorted(train_projects)
        report["inspected_comparison_projects"]=sorted(test_projects)
        report["prior_advisory_training_overlap_known"]=True
        report["official_training_data_gate_status_not_inferred"]=True
        report["adapter_artifact_sha256"]=manifest["sha256"]
        report["training_manifest_sha256"]=hashlib.sha256(args.training_manifest.read_bytes()).hexdigest()
        report["no_independent_ground_truth"]=True
        report["model_quality_validated"]=False
        report["network_eligible"]=False
        report["registration_authorized"]=False
        report["notice"]="These original four projects were publicly inspected, and Jinja/Axios advisories appeared in the prior GHSA training data. An improved score here is NOT clean unseen accuracy. AI proposals are unreviewed."
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n",encoding="utf-8")
        print(json.dumps({k:report[k] for k in (
            "status","ai_proposals_compared","model_agrees_with_ai_proposals",
            "families_matching_both_ai_proposals","human_reviews","network_eligible")},indent=2))
        return 0
    except (ComparisonError,ValueError,KeyError,TypeError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM PHASE2U MODEL COMPARE ERROR: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
