"""Phase 3K: explicit fact-sensitive *research-only* intervention on seen projects.

Starlette and Requests have verified historical installed-library behavior,
but these projects were already studied and scored. Research training is
allowed to inspect these diagnostics only by FORFEITING them as holdouts.
Nothing here is a human label, network evaluation row or release permission.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .phase3j_inputs import FAMILIES, proof
from .model_eval import render

STATUS = "PHASE3K_RESEARCH_INTERVENTION_KNOWN_FAMILIES_NO_NETWORK_TRAINING_APPROVAL"
VARIANTS = (
    ("v1", "Use only the installed-library observation, not an unverified production claim.",
     "This interpretation addresses the bounded historical library check only."),
    ("v2", "Make an evidence-limited assessment; do not assume a production exploit occurred.",
     "Only a controlled original framework method was examined, not a live deployment."),
)
SOURCE_PROJECTS = ("Kludex/starlette", "psf/requests")
TRANSFER_EXCLUDED = ("tornadoweb/tornado","nodejs/undici","python-websockets/websockets")


class InterventionError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode()


def validate_base(rows: list[dict]) -> None:
    if not isinstance(rows,list) or len(rows) != 52:
        raise InterventionError("expected exact 52 historical advisory training-only rows")
    if any(not isinstance(r,dict) or set(r)!={"prompt","chosen","rejected"}
           or not all(isinstance(r[k],str) and r[k].strip() for k in ("prompt","chosen","rejected"))
           or r["chosen"] == r["rejected"] for r in rows):
        raise InterventionError("base research rows malformed")
    if len({r["prompt"] for r in rows})!=52 or len({r["rejected"] for r in rows})!=52:
        raise InterventionError("duplicate original research examples")


def make_experiment(root: Path, base: list[dict]) -> tuple[list[dict],dict]:
    validate_base(base)
    provenance=proof(root)
    if len(FAMILIES)!=2 or [f["id"] for f in FAMILIES] != ["starlette-path-boundary","requests-proxy-auth"]:
        raise InterventionError("only two real observed already-studied families permitted")
    additions=[]
    for family in FAMILIES:
        if len(family["answers"]) != 2 or len(family["contexts"]) != 2:
            raise InterventionError("exactly two fixed answer strings and two contexts per family")
        if {c[2] for c in family["contexts"]} != {a[0] for a in family["answers"]}:
            raise InterventionError("both opposite chosen answers required")
        for variant,scope,shared_suffix in VARIANTS:
            texts={a[0]:a[1]+" "+shared_suffix for a in family["answers"]}
            for context_id,task,preferred in family["contexts"]:
                chosen=texts[preferred]
                rejected=texts[next(k for k in texts if k!=preferred)]
                prompt=task+" "+scope
                additions.append({"prompt":prompt,"chosen":chosen,"rejected":rejected})
            # The two contexts use precisely the SAME two strings, with inverted roles:
            left,right=additions[-2:]
            if (left["chosen"] != right["rejected"] or left["rejected"] != right["chosen"]
                or left["prompt"] == right["prompt"]):
                raise InterventionError("candidate text changed across counterfactual contexts")
    if len(additions)!=8:
        raise InterventionError("require exactly eight balanced research contrast rows")
    combined=base+additions
    if len({x["rejected"] for x in combined})!=len(combined) or len({x["prompt"] for x in combined})!=len(combined):
        raise InterventionError("trainer shortcut: repeated rejected response or duplicate question")
    lengths=[(len(x["chosen"].split()),len(x["rejected"].split())) for x in additions]
    if any(not 0.65<=a/b<=1.5 for a,b in lengths):
        raise InterventionError("prefer-longer-answer shortcut in context additions")
    manifest={
        "schema_version":1,"status":STATUS,"intent":"SECURITY_REVIEW_GENERAL",
        "training_data_provenance":"RESEARCH_ONLY_FROM_ALREADY_RESEARCHED_RUNTIME_CASES",
        "source_runtime_evidence":provenance,
        "seen_training_projects":list(SOURCE_PROJECTS),
        "already_inspected_transfer_projects_excluded":list(TRANSFER_EXCLUDED),
        "base_research_training_pairs":52,
        "known_runtime_context_training_pairs":len(additions),
        "training_pairs_total":len(combined),
        "balanced_reversal_families":2,
        "paired_writing_variants_per_family":2,
        "unmodified_answer_text_across_opposite_contexts":True,
        "source_research_author": "FALSUM_GENERATED_PROVISIONAL_PREFERENCES",
        "model_training_attempt_permitted_for_research_only":True,
        "training_or_labels_authorized_for_submittable_network_module":False,
        "previously_scored_starlette_requests_no_longer_valid_as_holdouts":True,
        "source_separated_transfer_previously_inspected_not_sealed":True,
        "independent_human_approved_labels":0,"accepted_anjoman_rows":0,
        "network_eligible":False,"registered_evaluator":False,
        "original_model_release_veto_remains":True,
        "additions_sha256":hashlib.sha256(canonical(additions)).hexdigest(),
        "full_training_data_sha256":hashlib.sha256(b"".join(canonical(r) for r in combined)).hexdigest(),
        "notice":"These eight model-training rows derive from two already observed historical runtime cases. They contaminate those seen-family diagnostics for any future claim of heldout accuracy. Source-separated transfer examples were previously inspected and are AI-provisional, not a blind or independently validated benchmark."
    }
    return combined,manifest


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Prepare research-only exact opposite-context training intervention")
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--base",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--manifest",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        paths=[a.base.resolve(),a.out.resolve(),a.manifest.resolve()]
        if len(set(paths))!=3 or a.out.exists() or a.manifest.exists():
            raise InterventionError("refuse output overwrite or source alias")
        base=[json.loads(s) for s in a.base.read_text().splitlines() if s.strip()]
        rows,report=make_experiment(a.root,base)
        payload=b"".join(canonical(row) for row in rows)
        if hashlib.sha256(payload).hexdigest()!=report["full_training_data_sha256"]:
            raise InterventionError("training bytes changed after validation")
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.manifest.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(payload)
        a.manifest.write_bytes(json.dumps(report,indent=2,sort_keys=True).encode()+b"\n")
        print(json.dumps({k:report[k] for k in ("status","training_pairs_total",
            "known_runtime_context_training_pairs","independent_human_approved_labels","network_eligible")},indent=2))
        return 0
    except (InterventionError,ValueError,TypeError,KeyError,OSError) as exc:
        p.exit(1,f"PHASE3K QUARANTINED TRAIN DATA ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
