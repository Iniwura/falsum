"""Capture authentic local application snippets into explicit unreviewed review claims.

The submitter chooses whether each stated prerequisite is "present"/"absent".
The software verifies and fills EXACT file SHA-256, full source line references
and quotes; it does NOT infer those assertions, verify their meaning, or certify
exploitability. No on-disk source files are edited.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import (
    INPUT_STATUS, MAX_BYTES, NAME, ProofError, _inside, validate_catalog,
    evaluate_case, verify_excerpt,
)


def capture_claims(rule:dict,root:Path,claims:list[dict])->dict:
    if not isinstance(claims,list) or not 1<=len(claims)<=24:
        raise ProofError("1..24 explicit unreviewed application claims required")
    allowed={x["id"] for x in rule["requirements"]}
    filled=[]
    for item in claims:
        if not isinstance(item,dict) or set(item)!={"requirement_id","claim","path","line_start","line_end"}:
            raise ProofError("unreviewed claim schema changed")
        req=item["requirement_id"]
        if not isinstance(req,str) or not NAME.fullmatch(req) or req not in allowed:
            raise ProofError("claim not in source-pinned requirement list")
        if item["claim"] not in ("present","absent"):
            raise ProofError("only explicitly asserted present or absent accepted")
        start,end=item["line_start"],item["line_end"]
        if (type(start) is not int or type(end) is not int or
                start<1 or end<start or end-start>14):
            raise ProofError("claim line interval invalid")
        path=_inside(root,item["path"])
        if path.stat().st_size>MAX_BYTES:
            raise ProofError("application excerpt source too large")
        contents=path.read_bytes()
        try:
            lines=contents.decode("utf-8").splitlines()
        except UnicodeDecodeError as e:
            raise ProofError("application file must be UTF-8") from e
        if end>len(lines):
            raise ProofError("claim line outside actual file")
        quote="\n".join(lines[start-1:end])
        witness={**item,"sha256":hashlib.sha256(contents).hexdigest(),"quote":quote}
        verify_excerpt(root,witness)
        filled.append(witness)
    result={"schema_version":1,"status":INPUT_STATUS,
            "case_id":rule["case_id"],"repository":rule["repository"],
            "source_commit":rule["source_commit"],
            "evidence_origin":"unreviewed_application_submission",
            "evidence":filled}
    # Even after extraction, don't claim real semantic verification.
    provisional=evaluate_case(rule,result,root)
    if provisional["actual_application_semantics_verified"] is not False:
        raise ProofError("unexpected automatic semantic promotion")
    return result


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Extract real immutable file citations for unreviewed application security assertions")
    for name in ("catalog","old-queue","train-queue","fresh-spec","case-id","claims","root","out"):
        p.add_argument("--"+name,type=str if name=="case-id" else Path,required=True)
    a=p.parse_args(argv)
    try:
        paths=[a.catalog,a.old_queue,a.train_queue,a.fresh_spec,a.claims,a.root,a.out]
        if a.out.exists() or any(a.out.resolve()==x.resolve() for x in paths[:-1]):
            raise ProofError("refusing to overwrite any input or application file")
        from .real_fix_corpus import load_queue
        fresh=json.loads(a.fresh_spec.read_text(encoding="utf-8"))
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False):
            raise ProofError("fresh source metadata lost quarantine")
        source=load_queue(a.old_queue)["cases"]+load_queue(a.train_queue)["cases"]+fresh["cases"]
        catalog=json.loads(a.catalog.read_text(encoding="utf-8"))
        rules=validate_catalog(catalog,source)
        if a.case_id not in rules:
            raise ProofError("unknown source case; cannot bind local proof to advisory")
        claims=json.loads(a.claims.read_text(encoding="utf-8"))
        if not isinstance(claims,dict) or set(claims)!={"status","claims"} or claims["status"]!="SUBMITTER_ASSERTIONS_UNREVIEWED":
            raise ProofError("input claims are not explicitly unreviewed assertions")
        result=capture_claims(rules[a.case_id],a.root,claims["claims"])
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({"case_id":a.case_id,"captured_verified_exact_excerpts":len(result["evidence"]),
                          "independent_semantic_reviews":0,"confirmed_vulnerabilities":0,
                          "network_eligible":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ProofError) as e:
        p.exit(1,f"FALSUM REAL APPLICATION CAPTURE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
