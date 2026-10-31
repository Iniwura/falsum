"""Audit frozen-model prior advisory exposure against two public source pools.

The earlier research LoRA was trained on the pinned GHSA training queue;
exact advisory and package overlap means inspected diagnostics are not a
novel blind holdout. Absence from THIS queue is NOT proof of zero exposure
through base pretraining, public internet, or any other draft curriculum.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from .real_fix_corpus import load_queue

STATUS = "PRIOR_GHSA_TRAINING_EXPOSURE_AUDIT_NOT_BLIND_HOLDOUT"
PACKAGE_ALIASES = {"pallets/jinja": ("jinja", "jinja2")}


class ExposureError(ValueError):
    pass


def audit(prior: dict, candidates: dict, inspected: dict) -> dict:
    if not isinstance(prior, dict) or prior.get("schema_version") != 1:
        raise ExposureError("invalid historical GHSA queue")
    entries = prior.get("advisories")
    if not isinstance(entries, list) or len(entries) < 10 or len(entries) > 500:
        raise ExposureError("unbounded or missing historic advisory rows")
    ghsa=set()
    pkgs={}
    by_ghsa={}
    for i,row in enumerate(entries):
        if (not isinstance(row,dict) or not isinstance(row.get("id"),str)
                or not row["id"].startswith("GHSA-")
                or not isinstance(row.get("package"),str) or not row["package"].strip()
                or row.get("split") not in ("train","validation","holdout")):
            raise ExposureError(f"invalid old GHSA row {i}")
        name=row["package"].casefold()
        if row["id"] in ghsa:
            raise ExposureError("duplicate historic GHSA")
        ghsa.add(row["id"])
        pkgs.setdefault(name,[]).append({"advisory":row["id"],"prior_split":row["split"]})
        by_ghsa[row["id"]]=row
    def section(pool: dict,name: str) -> dict:
        if pool.get("status")!="PUBLIC_PATCH_SOURCES_DRAFT_UNREVIEWED":
            raise ExposureError("source pool not research-only")
        records=[]
        for source in pool.get("cases",[]):
            repo=source["repository"]
            root=repo.split("/")[-1].casefold()
            aliases=PACKAGE_ALIASES.get(repo,(root,))
            exact=by_ghsa.get(source["advisory"])
            package_matches=[{"package":package,**r} for package in aliases for r in pkgs.get(package,[])]
            records.append({
                "case_id":source["id"],"source_project":repo,
                "source_advisory":source["advisory"],
                "advisory_id_seen_in_prior_queue":exact is not None,
                "exact_advisory_previous_split":exact["split"] if exact else None,
                "package_mentions_in_prior_queue":package_matches,
                "case_is_new_to_complete_model":False,
            })
        return {
            "pool":name,"records":records,
            "exact_advisory_matches":sum(x["advisory_id_seen_in_prior_queue"] for x in records),
            "project_package_overlap_count":sum(bool(x["package_mentions_in_prior_queue"]) for x in records)
        }
    return {
        "schema_version":1,"status":STATUS,
        "source": "data/advisory-queue.json pinned prior GHSA research curriculum inventory",
        "prior_advisory_count":len(entries),
        "research_only":True,"heldout_sealed":False,
        "independent_ground_truth":False,"model_accuracy_certified":False,
        "network_eligible":False,
        "pools":[section(candidates,"new_project_context_diagnostics"),
                 section(inspected,"historically_inspected_context_diagnostics")],
        "warning":"Overlap describes GHSA records in the prior pinned advisory queue ONLY. No overlap does not establish independence from base pretraining, synthetic PR curriculum or wider internet training. All current case labels are AI-authored.",
    }


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Expose exact advisory and project overlap with earlier frozen-model curriculum")
    p.add_argument("--prior",required=True,type=Path)
    p.add_argument("--new",required=True,type=Path)
    p.add_argument("--inspected",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        items=(args.prior,args.new,args.inspected,args.out)
        if len({x.resolve() for x in items})<4 or args.out.exists():
            raise ExposureError("refuse colliding source/output paths")
        prior=json.loads(args.prior.read_text(encoding="utf-8"))
        new,old=load_queue(args.new),load_queue(args.inspected)
        result=audit(prior,new,old)
        result["inputs_sha256"]={k:hashlib.sha256(f.read_bytes()).hexdigest() for k,f in
                                 (("prior",args.prior),("new",args.new),("inspected",args.inspected))}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"status":result["status"],"prior_rows":result["prior_advisory_count"],
                          "new_exact_advisory_overlap":result["pools"][0]["exact_advisory_matches"],
                          "inspected_exact_advisory_overlap":result["pools"][1]["exact_advisory_matches"],
                          "heldout_sealed":False,"network_eligible":False},indent=2))
        return 0
    except (ExposureError,OSError,ValueError,KeyError,TypeError) as e:
        p.exit(1,f"FALSUM PRIOR EXPOSURE AUDIT ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
