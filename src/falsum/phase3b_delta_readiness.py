"""Phase 3B: old research checkpoint -> NEW shared Foundation delta preflight.

No training, deployment or network registration. The old checkpoint's adapter
folder is checked against its PREVIOUSLY RECORDED byte-manifest digest; never
treat official lora-v1 structural checks as security-reasoning accuracy.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .model_eval import adapter_artifact_manifest

STATUS="PHASE3B_EXISTING_OLD_RESEARCH_ADAPTER_PINNED_FOR_SHARED_FOUNDATION_EXPORT"
PREVIOUS_MANIFEST="a20bdc0ffdc9ee776877e60b5c19c225d9279467d005916a6978db1650482d33"
SOURCE_RUN_ID=41283929744
SOURCE_ARTIFACT_ID=13074383795
EXPECTED_TRAIN_STATUS="AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK"


class DeltaReadinessError(ValueError):
    pass


def locate(root:Path)->tuple[Path,Path]:
    if not root.is_dir() or root.is_symlink():
        raise DeltaReadinessError("existing downloaded research artifact missing")
    if any(path.is_symlink() for path in root.rglob("*")):
        raise DeltaReadinessError("downloaded research artifact contains symlink")
    configs=list(root.rglob("adapter_config.json"))
    if len(configs)!=1:
        raise DeltaReadinessError("expected exactly one saved real LoRA")
    adapter=configs[0].parent
    manifests=list(root.rglob("PHASE2U-TRAIN-MANIFEST.json"))
    if len(manifests)!=1:
        raise DeltaReadinessError("missing exact source-labeled AI-provisional provenance")
    return adapter,manifests[0]


def inspect(root:Path,expected_sha:str=PREVIOUS_MANIFEST)->dict:
    adapter,manifest_path=locate(root)
    source=json.loads(manifest_path.read_text(encoding="utf-8"))
    if (source.get("status")!=EXPECTED_TRAIN_STATUS
        or source.get("network_eligible") is not False
        or source.get("training_authorized_for_submission") is not False
        or source.get("research_only") is not True
        or source.get("independent_human_reviews")!=0):
        raise DeltaReadinessError("training provenance wrongly promoted to approved material")
    evidence=adapter_artifact_manifest(adapter)
    if evidence["sha256"]!=expected_sha:
        raise DeltaReadinessError("saved old checkpoint no longer matches original file manifest")
    conf=json.loads((adapter/"adapter_config.json").read_text(encoding="utf-8"))
    if conf.get("peft_type")!="LORA" or conf.get("bias","none")!="none":
        raise DeltaReadinessError("not compatible modern lora-v1 basic PEFT config")
    r=conf.get("r")
    if type(r) is not int or not 1<=r<=16:
        raise DeltaReadinessError("rank outside shared foundation 1..16")
    mods=conf.get("target_modules") or []
    if not isinstance(mods,(list,tuple,set)) or not set(mods).issubset({"Wo","Wi","Wqkv"}):
        raise DeltaReadinessError("target modules differ from official shared foundation")
    if any(conf.get(key) for key in ("use_rslora","use_dora","rank_pattern","alpha_pattern")):
        raise DeltaReadinessError("unsupported LoRA variant in research checkpoint")
    return {
        "schema_version":1,"status":STATUS,
        "source_training_run":SOURCE_RUN_ID,
        "source_training_artifact_id":SOURCE_ARTIFACT_ID,
        "original_adapter_manifest_sha256":evidence["sha256"],
        "original_model_files_sha256":evidence["files"],
        "old_source_training_manifest_sha256":hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "source_training_projects":source["training_projects"],
        "original_training_source":"PHASE2U-AI-PROVISIONAL",
        "model_architecture":"ModernBERT LoRA",
        "rank":r,"target_modules":sorted(set(mods)),
        "adapter_relative_path":adapter.relative_to(root).as_posix(),
        "research_only":True,"independent_human_labels":0,
        "held_out_cross_project_context_transfer_demonstrated":False,
        "network_eligible":False,"registered_evaluator":False,
        "note":"Identity and basic PEFT compatibility only. Official exporter, official Go structural gate and independent model quality all remain separate checks."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Verify existing QUARANTINED checkpoint bytes and provenance before the 2026 node adapter format migration")
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.out.exists() or args.out.resolve().is_relative_to(args.root.resolve()):
            raise DeltaReadinessError("refuse overwriting existing checkpoint or output")
        packet=inspect(args.root)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(packet,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":STATUS,"saved_checkpoint_integrity_verified":True,
                          "training_source":"AI provisional","research_only":True,
                          "network_eligible":False},indent=2))
        return 0
    except (DeltaReadinessError,OSError,ValueError,KeyError,TypeError) as e:
        p.exit(1,f"FALSUM OLD-TO-NEW ADAPTER MIGRATION ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
