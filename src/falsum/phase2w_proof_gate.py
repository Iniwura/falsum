"""Fail-closed evidence-bound *applicability* gate for historical security findings.

Research-only. This does NOT prove exploitability or decide semantic correctness
of user-submitted code excerpts. Immutable local file hashes + exact line
citations establish integrity of submitted text, not truthful interpretation.
Every supported conclusion is a conditional REVIEW CANDIDATE, not confirmed
vulnerability, human security review or network-eligible model label.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

STATUS="RESEARCH_SOURCE_PINNED_APPLICABILITY_RULES_NOT_SECURITY_CERTIFICATION"
INPUT_STATUS="USER_SUPPLIED_APPLICATION_EVIDENCE_UNADJUDICATED"
REPORT_STATUS="EVIDENCE_FIRST_CONDITIONAL_FINDINGS_UNREVIEWED"
RULE_FIELDS={"case_id","repository","source_commit","source_blob","source_path",
             "source_advisory","source_kind","requirements"}
EVIDENCE_FIELDS={"requirement_id","claim","path","sha256","line_start","line_end","quote"}
HEX=re.compile(r"[0-9a-f]{64}\Z")
HEX40=re.compile(r"[0-9a-f]{40}\Z")
NAME=re.compile(r"[a-z][a-z0-9_-]{2,90}\Z")
SAFE_PATH=re.compile(r"[a-zA-Z0-9_.\-/]+\Z")
MAX_BYTES=128_000

class ProofError(ValueError):
    """Reject invalid evidence provenance instead of giving a confident verdict."""


def _canonical(x):
    return (json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")


def _bounded(value,name,low=1,high=600):
    if not isinstance(value,str) or not low<=len(value)<=high or "\x00" in value:
        raise ProofError(f"invalid {name} string")
    return value


def validate_catalog(catalog:dict,source_rows:list[dict]) -> dict[str,dict]:
    if (not isinstance(catalog,dict) or set(catalog)!={"schema_version","status","intent",
            "research_only","independent_human_reviews","network_eligible",
            "source_verification","rules"} or catalog["schema_version"]!=1
            or catalog["status"]!=STATUS or catalog["intent"]!="SECURITY_REVIEW_GENERAL"
            or catalog["research_only"] is not True
            or type(catalog["independent_human_reviews"]) is not int
            or catalog["independent_human_reviews"]!=0
            or catalog["network_eligible"] is not False):
        raise ProofError("catalog must remain source-pinned and research-only")
    rules=catalog["rules"]
    if not isinstance(rules,list) or len(rules)!=11 or len(source_rows)!=11:
        raise ProofError("exactly eleven verified-source identities expected")
    sources={r["id"]:r for r in source_rows}
    if len(sources)!=11 or len({s["repository"] for s in source_rows})!=11:
        raise ProofError("source identity or project duplicate")
    seen=set()
    for r in rules:
        if not isinstance(r,dict) or set(r)!=RULE_FIELDS:
            raise ProofError("unknown rule metadata")
        ident=r["case_id"]
        if ident in seen or ident not in sources:
            raise ProofError("duplicate or unknown source rule")
        seen.add(ident)
        upstream=sources[ident]
        for field,source_field in (("repository","repository"),("source_commit","commit"),
                                   ("source_blob","source_blob"),("source_path","source_path"),
                                   ("source_advisory","advisory")):
            if r[field]!=upstream[source_field]:
                raise ProofError(f"rule {ident} changed pinned upstream {field}")
        if not HEX40.fullmatch(r["source_commit"]) or not HEX40.fullmatch(r["source_blob"]):
            raise ProofError("untrusted upstream object identity")
        if r["source_kind"] not in ("historical-source-fix","fresh-public-transfer"):
            raise ProofError("unrecognized source provenance")
        needs=r["requirements"]
        if not isinstance(needs,list) or not 2<=len(needs)<=6:
            raise ProofError("2..6 explicit conjunctive conditions required")
        keys=set()
        for need in needs:
            if not isinstance(need,dict) or set(need)!={"id","explanation"}:
                raise ProofError("invalid precondition schema")
            if not isinstance(need["id"],str) or not NAME.fullmatch(need["id"]):
                raise ProofError("precondition name malformed")
            _bounded(need["explanation"],"precondition explanation",20,400)
            if need["id"] in keys:
                raise ProofError("duplicate precondition")
            keys.add(need["id"])
    if seen!=set(sources):
        raise ProofError("source case missing from catalog")
    return {r["case_id"]:r for r in rules}


def _inside(root:Path,rel:str)->Path:
    if (not isinstance(rel,str) or not 1<=len(rel)<=180 or not SAFE_PATH.fullmatch(rel)
            or rel.startswith("/") or "\\" in rel
            or any(x in ("",".","..") for x in rel.split("/"))):
        raise ProofError("invalid relative local evidence path")
    base=root.resolve(strict=True)
    cur=base
    for part in rel.split("/"):
        cur=cur/part
        # Don't follow a symlink even if the ultimate target is inside root.
        if cur.is_symlink():
            raise ProofError("evidence path contains symlink")
    resolved=cur.resolve(strict=True)
    if not resolved.is_relative_to(base) or not resolved.is_file():
        raise ProofError("evidence outside approved root or not a file")
    return resolved


def verify_excerpt(root:Path,evidence:dict)->dict:
    if not isinstance(evidence,dict) or set(evidence)!=EVIDENCE_FIELDS:
        raise ProofError("unexpected evidence fields or missing exact location")
    req=_bounded(evidence["requirement_id"],"precondition key",3,100)
    if not NAME.fullmatch(req) or evidence["claim"] not in ("present","absent"):
        raise ProofError("unrecognized claim or precondition ID")
    if not isinstance(evidence["sha256"],str) or not HEX.fullmatch(evidence["sha256"]):
        raise ProofError("missing exact application SHA-256")
    start,end=evidence["line_start"],evidence["line_end"]
    if (type(start) is not int or type(end) is not int or start<1 or end<start
            or end-start>14):
        raise ProofError("invalid evidence line window")
    _bounded(evidence["quote"],"exact application excerpt",2,4000)
    file=_inside(root,evidence["path"])
    if file.stat().st_size>MAX_BYTES:
        raise ProofError("file exceeds bounded evidence size")
    raw=file.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=evidence["sha256"]:
        raise ProofError("application source changed since evidence was captured")
    try:
        value=raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofError("invalid application evidence UTF-8") from exc
    lines=value.splitlines()
    if end>len(lines):
        raise ProofError("claimed source lines outside file")
    expected="\n".join(lines[start-1:end])
    if expected!=evidence["quote"]:
        raise ProofError("evidence quote is not the exact cited application text")
    return {"requirement_id":req,"claim":evidence["claim"],"path":evidence["path"],
            "sha256":evidence["sha256"],"line_start":start,"line_end":end,
            "machine_verified_exact_file_and_quote":True,
            "semantic_claim_independently_adjudicated":False}


def evaluate_case(rule:dict,manifest:dict,root:Path)->dict:
    if (not isinstance(manifest,dict) or set(manifest)!={"schema_version","status",
            "case_id","repository","source_commit","evidence_origin","evidence"} or
            manifest["schema_version"]!=1 or manifest["status"]!=INPUT_STATUS
            or manifest["case_id"]!=rule["case_id"]
            or manifest["repository"]!=rule["repository"]
            or manifest["source_commit"]!=rule["source_commit"]
            or manifest["evidence_origin"] not in ("synthetic_fixture","unreviewed_application_submission")):
        raise ProofError("manifest source identity or trust designation mismatch")
    provided=manifest["evidence"]
    if not isinstance(provided,list) or len(provided)>24:
        raise ProofError("evidence count exceeds bounded limit")
    allowed={x["id"]:x["explanation"] for x in rule["requirements"]}
    seen={}
    excerpts=[]
    for e in provided:
        check=verify_excerpt(root,e)
        if check["requirement_id"] not in allowed:
            raise ProofError("out-of-catalog application precondition")
        label=check["requirement_id"]
        seen.setdefault(label,[]).append(check)
        excerpts.append(check)
    conditions=[]
    for name,explanation in allowed.items():
        witnesses=seen.get(name,[])
        values={w["claim"] for w in witnesses}
        if len(values)>1:
            state="CONFLICT"
        elif values=={"present"}:
            state="ASSERTED_PRESENT"
        elif values=={"absent"}:
            state="ASSERTED_ABSENT"
        else:
            state="UNOBSERVED"
        conditions.append({"requirement_id":name,"description":explanation,
                           "evidence_state":state,"citations":[{
                               "path":w["path"],"sha256":w["sha256"],
                               "line_start":w["line_start"],"line_end":w["line_end"],
                               "claimed_state":w["claim"]} for w in witnesses]})
    states={x["evidence_state"] for x in conditions}
    if "CONFLICT" in states:
        result="CONFLICTING_APPLICATION_CLAIMS"
    elif "ASSERTED_ABSENT" in states:
        result="APPLICABILITY_PRECONDITION_CONTRADICTED"
    elif "UNOBSERVED" in states:
        result="INSUFFICIENT_APPLICATION_EVIDENCE"
    else:
        result="CONDITIONALLY_APPLICABLE_REVIEW_CANDIDATE"
    return {
        "case_id":rule["case_id"],"repository":rule["repository"],
        "source_commit":rule["source_commit"],"source_path":rule["source_path"],
        "source_blob":rule["source_blob"],
        "source_record":"IMMUTABLE_GIT_IDENTITY_PINNED_NOT_REPLAYED_IN_THIS_FUNCTION",
        "application_evidence_origin":manifest["evidence_origin"],
        "machine_integrity_verified_excerpts":len(excerpts),
        "actual_application_semantics_verified":False,
        "evidence_proves_exploitation":False,
        "result":result,"preconditions":conditions,
        "human_review_required":True,"confirmed_security_finding":False,
        "network_eligible":False,
        "review_guidance":"Inspect full application call graph and data flow. Exact excerpt integrity alone cannot prove truth of the submitter's present/absent assertions."
    }


def evaluate_batch(catalog:dict,source_rows:list[dict],batch:dict,root:Path)->dict:
    rules=validate_catalog(catalog,source_rows)
    if (not isinstance(batch,dict) or set(batch)!={"schema_version","status","research_only","scenarios"}
            or batch["schema_version"]!=1
            or batch["status"]!="UNREVIEWED_APPLICATION_EVIDENCE_BATCH"
            or batch["research_only"] is not True or not isinstance(batch["scenarios"],list)
            or not 1<=len(batch["scenarios"])<=100):
        raise ProofError("invalid batch or attempted release-status promotion")
    rows=[evaluate_case(rules.get(m.get("case_id")) if isinstance(m,dict) else None,m,root)
          for m in batch["scenarios"]]
    keys=[(x["case_id"],str(i)) for i,x in enumerate(rows)]
    if len(rows)!=len(keys):
        raise ProofError("duplicate scenario processing")
    counts={k:sum(r["result"]==k for r in rows) for k in (
        "CONDITIONALLY_APPLICABLE_REVIEW_CANDIDATE",
        "APPLICABILITY_PRECONDITION_CONTRADICTED",
        "INSUFFICIENT_APPLICATION_EVIDENCE",
        "CONFLICTING_APPLICATION_CLAIMS")}
    return {
        "schema_version":1,"status":REPORT_STATUS,"intent":"SECURITY_REVIEW_GENERAL",
        "research_only":True,"source_pinned":True,"source_replayed_in_this_call":False,
        "application_exact_excerpt_integrity_verified":True,
        "application_assertions_independently_verified":False,
        "confirmed_exploits":0,"independent_human_reviews":0,
        "network_eligible":False,"accepted_evaluation_labels":0,
        "results":rows,"counts":counts,
        "source_catalog_sha256":hashlib.sha256(_canonical(catalog)).hexdigest(),
        "input_batch_sha256":hashlib.sha256(_canonical(batch)).hexdigest(),
        "caution":"All scenarios and asserted interpretations remain unreviewed. The engine proves cited local bytes matched their stated hashes/lines and computes precondition logic, NOT real vulnerability correctness or exploitability."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Strict source-pinned precondition checks on hash- and line-bound application evidence")
    for name in ("catalog","old-queue","train-queue","fresh-spec","batch","root","out"):
        p.add_argument("--"+name,type=Path,required=True)
    args=p.parse_args(argv)
    try:
        paths=[args.catalog,args.old_queue,args.train_queue,args.fresh_spec,args.batch,args.root,args.out]
        if args.out.exists() or any(args.out.resolve()==x.resolve() for x in paths[:-1]):
            raise ProofError("refuse to overwrite evidence or alias research input")
        from .real_fix_corpus import load_queue
        originals=load_queue(args.old_queue)["cases"]
        train=load_queue(args.train_queue)["cases"]
        fresh=json.loads(args.fresh_spec.read_text(encoding="utf-8"))
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False
                or fresh.get("independent_human_reviews")!=0):
            raise ProofError("fresh source identity list not quarantined")
        sources=originals+train+fresh["cases"]
        rules=json.loads(args.catalog.read_text(encoding="utf-8"))
        batch=json.loads(args.batch.read_text(encoding="utf-8"))
        report=evaluate_batch(rules,sources,batch,args.root)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(report))
        print(json.dumps({"status":REPORT_STATUS,"research_cases":len(report["results"]),
                          "counts":report["counts"],"confirmed_exploits":0,
                          "independent_human_reviews":0,"network_eligible":False},indent=2))
        return 0
    except (ProofError,KeyError,ValueError,TypeError,OSError) as e:
        p.exit(1,f"FALSUM EVIDENCE FIRST GATE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
