"""Phase 4O-v2: transparently revise six source-specific answers after bias audit.

The original Phase 4G 14-case public research pack stays unchanged. These
post-audit edits improve candidate length balance without changing any
researcher's answer hypothesis, question or upstream source citation.

NOT BLIND, NOT EXPERT GOLD, NOT NETWORK ELIGIBLE. Public changes may themselves
leak the author's preference; these revised answers are research material,
not a blinded evaluation holdout.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path

from .phase4g_reasoning_puzzles import build as original_build, SPECS

STATUS = "PHASE4O_POST_AUDIT_REVISED_SIX_ANSWERS_NOT_GOLD_NOT_BLIND"
# Revision choices were selected *after* an audit showed 13/14 original
# author-preferred answers had more characters. This is transparent
# material revision, not an independent predeclared holdout improvement.
CHANGES = {
    "requests-https-prepared": (
        "It omits Proxy-Authorization on this HTTPS request; the proxy adapter may handle credentials separately.",
        "Same HTTPS header exclusion; concise handling of the separate adapter path."
    ),
    "requests-http-prepared": (
        "It sets Proxy-Authorization for the HTTP request when proxy credentials exist.",
        "Same conditional HTTP credential branch without redundant prose."
    ),
    "jinja-existing-attribute": (
        "It uses environment.getattr so the sandbox policy checks attribute access.",
        "Same sandbox delegation; source-branch statement is now concise."
    ),
    "axios-absolute-disabled": (
        "It combines baseURL and the absolute target because allowAbsoluteUrls is false.",
        "Same explicit-false option branch; avoid explanatory padding."
    ),
    "starlette-prefix-sibling": (
        "commonprefix may admit this sibling; commonpath sees it is outside the static root.",
        "Same prefix-versus-path containment distinction, phrased precisely."
    ),
    "urllib3-default-lowercase": (
        "It lowercases header names before stripping authorization on a cross-host redirect.",
        "Same normalized cross-origin credential stripping behavior, fewer words."
    ),
}
REVISED_CASE_COUNT = 6


class RevisionError(ValueError):
    pass


def req(condition: bool, message: str) -> None:
    if not condition:
        raise RevisionError(message)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def build(source: dict) -> dict:
    original, diag = original_build(source)
    require_cases = original["cases"]
    req(len(require_cases) == 14 and len(CHANGES) == REVISED_CASE_COUNT,
        "revised material must preserve fourteen original cases and exactly six edits")
    choices = {case_id: (a,b,correct) for case_id,_,_,a,b,correct,*_ in SPECS}
    req(set(CHANGES).issubset(choices), "unknown author case in revision")
    revised=copy.deepcopy(original)
    events=[]
    for row in revised["cases"]:
        case_id=row["case_id"]
        if case_id not in CHANGES:
            continue
        new_text, explanation=CHANGES[case_id]
        a,b,preferred=choices[case_id]
        old_text=a if preferred=="A" else b
        other_text=b if preferred=="A" else a
        req(isinstance(new_text,str) and 65 <= len(new_text) <= 130 and
            new_text != old_text and new_text != other_text,
            "revision is trivial, implausible or identical to incorrect candidate")
        old_hash,new_hash=digest(old_text),digest(new_text)
        touched=0
        for presentation in row["presentations"]:
            req(presentation["expert_label"] is None and
                presentation["model_score"] is None,
                "revised material must not contain expert gold or model scores")
            for answer in presentation["candidate_answers"]:
                if answer["sha256"]==old_hash:
                    req(answer["text"] == old_text, "original candidate hash collision")
                    answer["text"]=new_text
                    answer["sha256"]=new_hash
                    touched+=1
        req(touched==2, "edited answer must occur exactly once in both A/B orders")
        req(row["expert_label"] is None and row["trainable"] is False
            and row["network_eligible"] is False,
            "revision cannot make gold or authorized training material")
        events.append({
            "case_id":case_id,
            "old_candidate_sha256":old_hash,
            "revised_candidate_sha256":new_hash,
            "reason":explanation,
            "posthoc_selection_disclosed":True,
            "external_expert_label":None,
        })
    req(len(events)==REVISED_CASE_COUNT and
        {x["case_id"] for x in events}==set(CHANGES),
        "not all six revision events preserved")
    for row in revised["cases"]:
        original_case=next(x for x in original["cases"] if x["case_id"]==row["case_id"])
        req(row["question"]==original_case["question"] and
            row["fix_commit"]==original_case["fix_commit"] and
            row["source_file_url"]==original_case["source_file_url"] and
            row["regression_test_file_url"]==original_case["regression_test_file_url"] and
            row["advisory_url"]==original_case["advisory_url"],
            "question or upstream source identity changed while balancing answer texts")
    revised["status"]=STATUS
    revised["material_version"]="post_audit_v2"
    revised["original_phase4g_structured_sha256"]=digest(
        json.dumps(original,sort_keys=True,separators=(",",":")))
    revised["modified_answer_cases"]=REVISED_CASE_COUNT
    revised["post_audit_bias_selection_and_author_preference_possible_leak"]=True
    revised["unreviewed_research_only"]=True
    revised["blind_or_sealed_holdout"]=False
    revised["independent_appsec_gold_labels"]=0
    revised["new_network_eligible_rows"]=0
    revised["revisions"]=events
    revised["warning"]=(
        "Six original researcher-preferred answer texts shortened AFTER length-bias "
        "diagnosis. All original questions, pinned sources, answer hypotheses and "
        "A/B swaps preserved. Historical Phase 4G data is unchanged. Public edit "
        "history reveals a possible author-label clue, so NOT blinded and NOT "
        "independent benchmark evidence. No trained-model or network quality claims."
    )
    return revised


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description="Write source-locked post-audit unreviewed material revision")
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    try:
        req(not args.out.exists() and not args.out.is_symlink(),
            "refuse replacing immutable evidence output")
        req(args.source.resolve()!=args.out.resolve(),"output aliases source")
        raw=args.source.read_bytes()
        req(0<len(raw)<=600_000,"source report out of bounds")
        data=build(json.loads(raw))
        args.out.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)
        with os.fdopen(fd,"w",encoding="utf-8") as fh:
            json.dump(data,fh,sort_keys=True,indent=2)
            fh.write("\n")
        print(json.dumps({
            "status":data["status"],"original_conditions":14,
            "revised_answer_texts":data["modified_answer_cases"],
            "original_source_unchanged":True,"independent_appsec_gold_labels":0,
            "sealed_holdout":False,"out":str(args.out)
        },indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,IndexError) as exc:
        p.exit(1,"FALSUM RESEARCH-ONLY CASE REVISION REFUSED: "+str(exc)[:170]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
