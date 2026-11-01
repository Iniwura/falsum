"""Generate 44 clearly labelled synthetic evidence integrity/logic tests.

The local files do not represent production applications or tested exploits.
All asserted meanings are AI research fixtures. Real users must provide their
own repository files and inspect findings manually.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from .phase2w_proof_gate import INPUT_STATUS, ProofError, validate_catalog

OUT_STATUS="UNREVIEWED_APPLICATION_EVIDENCE_BATCH"


def generate(catalog:dict,sources:list[dict],root:Path)->dict:
    rules=validate_catalog(catalog,sources)
    if root.exists():
        raise ProofError("synthetic evidence directory already exists; refuse overwrite")
    modes=("exposure","absent","unknown","conflicting")
    plans=[]
    # Finish computing all required synthetic case material before writing.
    for rule in rules.values():
        conditions=[r["id"] for r in rule["requirements"]]
        for mode in modes:
            observations=[]
            for i,name in enumerate(conditions):
                if mode=="unknown" and i==len(conditions)-1:
                    continue
                claims=["present"]
                if mode=="absent" and i==0:
                    claims=["absent"]
                if mode=="conflicting" and i==0:
                    claims=["present","absent"]
                for claim in claims:
                    line=f"SIMULATED CLAIM: {name} = {claim}. NOT LIVE APP DATA."
                    observations.append((name,claim,line))
            payload="\n".join(x[2] for x in observations)+"\n"
            data=payload.encode("utf-8")
            rel=f'{rule["case_id"]}/{mode}.txt'
            src_sha=hashlib.sha256(data).hexdigest()
            evidence=[{"requirement_id":name,"claim":claim,
                       "path":rel,"sha256":src_sha,
                       "line_start":i+1,"line_end":i+1,
                       "quote":line} for i,(name,claim,line) in enumerate(observations)]
            manifest={"schema_version":1,"status":INPUT_STATUS,
                      "case_id":rule["case_id"],"repository":rule["repository"],
                      "source_commit":rule["source_commit"],
                      "evidence_origin":"synthetic_fixture","evidence":evidence}
            plans.append((rel,data,manifest))
    root.mkdir(parents=True)
    for rel,data,_ in plans:
        path=root/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    return {"schema_version":1,"status":OUT_STATUS,"research_only":True,
            "scenarios":[x[2] for x in plans]}


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Generate purely synthetic 11x4 precondition logic research fixtures")
    for name in ("catalog","old-queue","train-queue","fresh-spec","root","out"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists() or a.root.exists() or a.out.resolve().is_relative_to(a.root.resolve()):
            raise ProofError("demo output and root must be new, distinct paths")
        from .real_fix_corpus import load_queue
        catalog=json.loads(a.catalog.read_text())
        first=load_queue(a.old_queue)["cases"]
        second=load_queue(a.train_queue)["cases"]
        fresh=json.loads(a.fresh_spec.read_text())
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("research_only") is not True
                or fresh.get("network_eligible") is not False):
            raise ProofError("source inventory is no longer research-only")
        output=generate(catalog,first+second+fresh["cases"],a.root)
        if len(output["scenarios"])!=44:
            raise ProofError("unexpected research proof case count")
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(output,sort_keys=True,indent=2)+"\n")
        print(json.dumps({"status":OUT_STATUS,"synthetic_scenarios":44,
                          "actual_applications_tested":0,"human_reviewed":0,
                          "network_eligible":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ProofError) as e:
        p.exit(1,f"FALSUM SYNTHETIC APP EVIDENCE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
