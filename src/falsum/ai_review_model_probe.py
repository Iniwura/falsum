"""Research-only scoring of four public-source AI-authored context reversals.

This is a provisional diagnostic of the frozen, previously trained ModernBERT
adapter. AI-authored preferred choices are NOT independent ground truth.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Callable

from .model_eval import ModernBertAdapterScorer, adapter_artifact_manifest

PUBLIC_STATUS = "AI_ASSISTED_DRAFT_COMPARISONS_NOT_INDEPENDENTLY_VALIDATED"
KEY_STATUS = "AI_PROPOSED_ANSWER_KEY_NOT_APPROVED"
REPORT_STATUS = "PROVISIONAL_AI_CONTEXT_DIAGNOSTIC_NOT_INDEPENDENT_ACCURACY"


class ProvisionalProbeError(ValueError):
    """Scoring/reporting data could not be trusted; no inferred accuracy."""


def _canonical(x: object) -> bytes:
    return (json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def _verify(public: dict, key: dict) -> list[tuple[dict, dict]]:
    if (not isinstance(public, dict) or not isinstance(key, dict)
            or public.get("status") != PUBLIC_STATUS
            or key.get("status") != KEY_STATUS
            or public.get("intent") != "SECURITY_REVIEW_GENERAL"
            or public.get("human_reviews") != 0 or key.get("human_reviews") != 0
            or public.get("model_training_authorized") is not False
            or key.get("model_training_authorized") is not False
            or public.get("network_eligible") is not False
            or key.get("network_eligible") is not False
            or public.get("sealed_holdout") is not False
            or key.get("public_packet_sha256") != hashlib.sha256(_canonical(public)).hexdigest()):
        raise ProvisionalProbeError("tampered AI draft packet or missing quarantine provenance")
    cases, entries=public.get("cases"),key.get("entries")
    if not isinstance(cases,list) or not isinstance(entries,list) or len(cases)!=8 or len(entries)!=8:
        raise ProvisionalProbeError("expected exactly eight provisional public/private records")
    seen=set()
    families=defaultdict(list)
    verified=[]
    for question,review in zip(cases,entries):
        if not isinstance(question,dict) or not isinstance(review,dict):
            raise ProvisionalProbeError("malformed model question or review evidence")
        if set(question)!={"case_id","question","candidate_a","candidate_b"}:
            raise ProvisionalProbeError("a public question has leaked label or unexpected fields")
        case_id=question["case_id"]
        if (not isinstance(case_id,str) or ":" not in case_id or case_id in seen
                or case_id!=review.get("case_id")
                or review.get("source_case")!=case_id.split(":")[0]
                or review.get("proposed_kind") not in ("finding","conditional")
                or review.get("proposed_preferred") not in ("A","B")
                or review.get("research_provenance")!="AI_AUTHORED_HYPOTHETICAL_CONTEXT_NOT_HUMAN_REVIEWED"
                or review.get("eligible") is not False
                or review.get("human_validated") is not False):
            raise ProvisionalProbeError("duplicate, mismatched or promoted provisional preference")
        for field in ("question","candidate_a","candidate_b"):
            if not isinstance(question[field],str) or len(question[field])<60:
                raise ProvisionalProbeError("truncated research question or candidate")
        if question["candidate_a"]==question["candidate_b"]:
            raise ProvisionalProbeError("identical candidate responses")
        seen.add(case_id)
        families[review["source_case"]].append((question,review))
        verified.append((question,review))
    if len(families)!=4:
        raise ProvisionalProbeError("requires four unrelated real-source projects")
    for family,items in families.items():
        if (len(items)!=2 or
                {x[1]["proposed_kind"] for x in items}!={"finding","conditional"} or
                {x[0]["candidate_a"],x[0]["candidate_b"]} !=
                {items[1][0]["candidate_a"],items[1][0]["candidate_b"]}):
            raise ProvisionalProbeError(f"{family}: candidate text or context pair leaked")
        a,b=items
        chosen=lambda item:(item[0]["candidate_a"] if item[1]["proposed_preferred"]=="A"
                             else item[0]["candidate_b"])
        if chosen(a)==chosen(b):
            raise ProvisionalProbeError("provisional preferred answer did not reverse")
    return verified


def evaluate(public: dict,key: dict,score_fn: Callable[[str,str],float]) -> dict:
    verified=_verify(public,key)
    cache={}
    def score(prompt: str,answer: str) -> float:
        cache_key=(prompt,answer)
        if cache_key not in cache:
            raw=score_fn(prompt,answer)
            if (type(raw) not in (int,float) or not math.isfinite(raw)):
                raise ProvisionalProbeError("model emitted non-finite or invalid score")
            cache[cache_key]=float(raw)
        return cache[cache_key]

    rows=[]
    for q,k in verified:
        a,b=score(q["question"],q["candidate_a"]),score(q["question"],q["candidate_b"])
        no_a,no_b=score("",q["candidate_a"]),score("",q["candidate_b"])
        if not math.isfinite(a-b) or not math.isfinite(no_a-no_b):
            raise ProvisionalProbeError("non-finite score margin")
        direction=1 if k["proposed_preferred"]=="A" else -1
        margin=direction*(a-b)
        ablated=direction*(no_a-no_b)
        rows.append({
            "case_id":q["case_id"],"source_case":k["source_case"],
            "proposed_kind":k["proposed_kind"],
            "score_a":a,"score_b":b,
            "ai_proposed_margin":margin,
            "answer_only_margin":ablated,
            "agrees_with_ai_proposal":margin>0,
            "ties":margin==0,
        })
    per_family={}
    for case in sorted({r["source_case"] for r in rows}):
        pair=[r for r in rows if r["source_case"]==case]
        per_family[case]={
            "contexts":2,
            "matches_both_ai_proposals":all(r["agrees_with_ai_proposal"] for r in pair),
            "matches_count":sum(r["agrees_with_ai_proposal"] for r in pair),
            "answer_only_cannot_pass_both":not all(r["answer_only_margin"]>0 for r in pair),
            "provisional_margins":[r["ai_proposed_margin"] for r in pair],
        }
        if len(pair)!=2 or not per_family[case]["answer_only_cannot_pass_both"]:
            raise ProvisionalProbeError("answer-only shortcut supposedly solves both opposed contexts")
    matches=sum(r["agrees_with_ai_proposal"] for r in rows)
    ties=sum(r["ties"] for r in rows)
    return {
        "schema_version":1, "status":REPORT_STATUS,
        "intent":"SECURITY_REVIEW_GENERAL","model_training_performed":False,
        "source":"real pre-fix code with AI-authored hypothetical deployment facts and pair preferences",
        "ai_proposals_compared":len(rows),
        "model_agrees_with_ai_proposals":matches,
        "ai_agreement_fraction":round((matches+0.5*ties)/len(rows),6),
        "ai_agreement_is_not_accuracy":True,
        "two_context_families":len(per_family),
        "families_matching_both_ai_proposals":sum(x["matches_both_ai_proposals"] for x in per_family.values()),
        "distinct_model_inferences":len(cache),
        "family_details":per_family,"case_scores":rows,
        "human_reviews":0,"accepted_evaluation_pairs":0,
        "network_eligible":False,"registration_authorized":False,
        "sealed_holdout":False,"model_quality_validated":False,
        "notice":"Provisional AI agreements on 8 publicly inspected, synthetic-context source examples are not independent accuracy, an untouched holdout, eligible Anjoman contributions or a green light to register.",
    }


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Score real ModernBERT vs AI-provisional opposite deployment contexts")
    p.add_argument("--public",type=Path,required=True)
    p.add_argument("--key",type=Path,required=True)
    p.add_argument("--adapter",type=Path,required=True)
    p.add_argument("--official-pilot",type=Path,required=True)
    p.add_argument("--counterfactual",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        if args.out.exists() or args.out.resolve() in {x.resolve() for x in (
                args.public,args.key,args.official_pilot,args.counterfactual)}:
            raise ProvisionalProbeError("will not overwrite inputs or prior research report")
        public=json.loads(args.public.read_text(encoding="utf-8"))
        key=json.loads(args.key.read_text(encoding="utf-8"))
        _verify(public,key)
        decision=json.loads(args.official_pilot.read_text(encoding="utf-8"))
        counter=json.loads(args.counterfactual.read_text(encoding="utf-8"))
        manifest=adapter_artifact_manifest(args.adapter)
        if (decision.get("status")!="BLOCKED_RESEARCH_ONLY"
                or decision.get("registration_authorized") is not False
                or decision.get("network_eligible") is not False
                or decision.get("adapter_sha256")!=manifest["sha256"]
                or counter.get("adapter_artifact",{}).get("sha256")!=manifest["sha256"]
                or counter.get("not_network_eligible") is not True):
            raise ProvisionalProbeError("real original scored model provenance not verified")
        scorer=ModernBertAdapterScorer(str(args.adapter))
        report=evaluate(public,key,scorer)
        report["actual_model_adapter_sha256"]=manifest["sha256"]
        report["public_packet_sha256"]=hashlib.sha256(args.public.read_bytes()).hexdigest()
        report["pinned_original_model_research_verdict"]=decision["status"]
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(report))
        print(json.dumps({k:report[k] for k in (
            "status","ai_proposals_compared","model_agrees_with_ai_proposals",
            "ai_agreement_fraction","two_context_families",
            "families_matching_both_ai_proposals","distinct_model_inferences",
            "human_reviews","network_eligible")},indent=2))
        return 0
    except (ProvisionalProbeError,ValueError,TypeError,KeyError,OSError,ImportError) as exc:
        p.exit(1,f"FALSUM PROVISIONAL MODEL DIAGNOSTIC ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
