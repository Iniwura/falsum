"""Phase 2U: narrow, AI-provisional context-transfer TRAIN curriculum.

This is deliberately a *research intervention* on the already inspected
Phase 2T source projects, NOT a new independently adjudicated training set.
The original four Phase 2S projects are never included in this curriculum.
No claims about unseen holdout accuracy or network eligibility are permitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .ai_review_model_probe import _verify
from .phase2t_project_isolation import validate_pools
from .phase2t_prior_exposure import audit
from .real_fix_corpus import load_queue

STATUS = "AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK"
SUFFIX = "Assessment scope: fictional service configuration; the proposed conclusion must be verified against its application code."

class TransferError(ValueError):
    """Reject role promotion, provenance drift or duplicate negatives."""


def _sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _canonical(data: object) -> bytes:
    return (json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def make_context_pairs(public: dict, proposed: dict, old_queue: dict,
                       new_queue: dict, prior: dict) -> tuple[list[dict], dict]:
    _verify(public, proposed)
    partition = validate_pools(new_queue, old_queue)
    exposure = audit(prior, new_queue, old_queue)
    if (partition["project_separation_verified"] is not True or
            exposure["pools"][0]["exact_advisory_matches"] != 0 or
            exposure["pools"][0]["project_package_overlap_count"] != 0):
        raise TransferError("training project leaked into historical GHSA curriculum or older inspected projects")
    pairs=[]
    selected_ids=[]
    family_kinds={}
    for question,key in zip(public["cases"],proposed["entries"]):
        family=key["source_case"]
        if family not in {r["id"] for r in new_queue["cases"]}:
            raise TransferError("source provenance outside training-project allowlist")
        if question["case_id"]!=key["case_id"]:
            raise TransferError("question/key order mismatch")
        chosen = question["candidate_a"] if key["proposed_preferred"]=="A" else question["candidate_b"]
        rejected=question["candidate_b"] if key["proposed_preferred"]=="A" else question["candidate_a"]
        # A neutral research-only sentence is appended to BOTH alternatives.
        # It prevents verbatim duplicate negative exports, but conveys no
        # chosen-versus-rejected tell. The original exact-essay reversals are
        # retained separately as diagnostic examples, never labelled clean.
        case_ref=question["case_id"]
        note=f"{SUFFIX} Research record {hashlib.sha256(case_ref.encode()).hexdigest()[:12]}."
        chosen=chosen+"\n\n"+note
        rejected=rejected+"\n\n"+note
        pairs.append({"prompt":question["question"],"chosen":chosen,"rejected":rejected})
        selected_ids.append(case_ref)
        family_kinds.setdefault(family,set()).add(key["proposed_kind"])
    if (len(pairs)!=8 or len(set(selected_ids))!=8 or len(family_kinds)!=4
            or any(kinds!={"finding","conditional"} for kinds in family_kinds.values())):
        raise TransferError("must use exactly both research contexts for four disjoint training projects")
    if len({x["rejected"] for x in pairs})!=len(pairs):
        raise TransferError("duplicate negative answers disallowed")
    if len({x["prompt"] for x in pairs})!=len(pairs):
        raise TransferError("duplicate training question")
    manifest={
        "schema_version":1,"status":STATUS,
        "intent":"SECURITY_REVIEW_GENERAL",
        "research_only":True, "prior_ai_draft_inspected":True,
        "training_projects":sorted({r["repository"] for r in new_queue["cases"]}),
        "excluded_projects":sorted({r["repository"] for r in old_queue["cases"]}),
        "research_pair_count":len(pairs),"source_family_count":len(family_kinds),
        "historical_train_exact_advisory_overlap":0,
        "official_gate_passed":False,
        "independent_human_reviews":0,
        "network_eligible":False,
        "training_authorized_for_submission":False,
        "independent_accuracy_established":False,
        "external_evaluation_is_sealed":False,
        "ai_source_packet_sha256":_sha(_canonical(public)),
        "ai_proposal_key_sha256":_sha(_canonical(proposed)),
        "pair_rows_sha256":_sha(_canonical(pairs)),
        "notice":"Training on publicly inspected AI-proposed research comparisons, with original source projects excluded. Passing official data shortcut checks only verifies the data format/shortcut heuristics, NOT human label accuracy or model eligibility."
    }
    return pairs,manifest


def append_train(base: list[dict], extras: list[dict], manifest: dict) -> tuple[list[dict],dict]:
    if (manifest.get("status")!=STATUS or manifest.get("network_eligible") is not False
            or manifest.get("independent_human_reviews")!=0 or len(extras)!=8
            or not isinstance(base,list) or len(base)<50):
        raise TransferError("not a permitted quarantined base train + eight-context recipe")
    if any(not isinstance(x,dict) or set(x)!={"prompt","chosen","rejected"} for x in base+extras):
        raise TransferError("unexpected training row fields")
    rows=base+extras
    if len({x["rejected"] for x in rows})!=len(rows):
        raise TransferError("duplicate negative response in combined corpus")
    if len({x["prompt"] for x in rows})!=len(rows):
        raise TransferError("duplicate task in combined corpus")
    manifest=dict(manifest)
    manifest["base_advisory_train_rows"]=len(base)
    manifest["new_research_context_train_rows"]=len(extras)
    manifest["total_train_rows"]=len(rows)
    manifest["combined_sha256"]=_sha("".join(json.dumps(x, separators=(",",":"),ensure_ascii=False)+"\n" for x in rows).encode())
    return rows,manifest


def main(argv: list[str]|None=None) -> int:
    p=argparse.ArgumentParser(description="AI provisional context training intervention only")
    for name in ("public","key","train-queue","old-queue","prior-advisories","baseline-train","out","manifest"):
        p.add_argument("--"+name,required=True,type=Path)
    args=p.parse_args(argv)
    inputs=[args.public,args.key,args.train_queue,args.old_queue,args.prior_advisories,args.baseline_train]
    if len({x.resolve() for x in inputs+[args.out,args.manifest]})!=8:
        p.exit(1,"FALSUM PHASE2U ERROR: input and output paths must be disjoint\n")
    if args.out.exists() or args.manifest.exists():
        p.exit(1,"FALSUM PHASE2U ERROR: refusing to overwrite research data\n")
    try:
        public=json.loads(args.public.read_text(encoding="utf-8"))
        key=json.loads(args.key.read_text(encoding="utf-8"))
        prior=json.loads(args.prior_advisories.read_text(encoding="utf-8"))
        train_q=load_queue(args.train_queue)
        old_q=load_queue(args.old_queue)
        extras,manifest=make_context_pairs(public,key,old_q,train_q,prior)
        base=[json.loads(x) for x in args.baseline_train.read_text(encoding="utf-8").splitlines() if x.strip()]
        rows,manifest=append_train(base,extras,manifest)
        # In-memory whole payload constructed before writing any output.
        payload="".join(json.dumps(x,separators=(",",":"),ensure_ascii=False)+"\n" for x in rows)
        if _sha(payload.encode())!=manifest["combined_sha256"]:
            raise TransferError("joined research train payload integrity mismatch")
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.manifest.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(payload,encoding="utf-8")
        args.manifest.write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({k:manifest[k] for k in (
            "status","base_advisory_train_rows","new_research_context_train_rows",
            "total_train_rows","independent_human_reviews","network_eligible")},indent=2))
        return 0
    except (TransferError,ValueError,OSError,TypeError,KeyError) as exc:
        p.exit(1,f"FALSUM PHASE2U ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
