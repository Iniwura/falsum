"""Three untrained public-project transfer diagnostics, with exact upstream patch replay.

Pre-fix source-only, source-test byte identity, private AI-proposed label key.
NOT a sealed holdout, expert verdict, train input or eligible network dataset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from .real_fix_corpus import fetch_github_commit, _selected_patch
from .real_fix_replay import apply_patch, fetch_raw, git_blob_sha, raw_url
from .pre_fix_challenges import parent_regions, ADVISORY_ID, LANGUAGES, FENCE
from .real_fix_corpus import load_queue
from .model_eval import render

STATUS = "FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
PUBLIC = "THREE_NEW_PUBLIC_SOURCE_AI_DRAFTS_NOT_EXPERT_GROUND_TRUTH"
PRIVATE = "THREE_NEW_PUBLIC_SOURCE_AI_PROPOSED_KEY_UNAPPROVED"
CASE_FIELDS = {"id","repository","commit","parent","source_path","source_blob",
               "test_path","test_blob","upstream_evidence","advisory",
               "research_limitation","finding_answer","conditional_answer","scenarios"}


class FreshTransferError(ValueError):
    pass


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj: object) -> bytes:
    return (json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False)+"\n").encode("utf-8")


def validate(spec: dict, train: dict, inspected: dict, prior: dict) -> list[dict]:
    if (not isinstance(spec,dict) or
            set(spec)!={"schema_version","status","intent","research_only",
                       "independent_human_reviews","model_training_authorized",
                       "network_eligible","heldout_sealed","notice","cases"} or
            spec.get("schema_version")!=1 or spec.get("status")!=STATUS
            or spec.get("intent")!="SECURITY_REVIEW_GENERAL"
            or spec.get("research_only") is not True
            or type(spec.get("independent_human_reviews")) is not int
            or spec.get("independent_human_reviews")!=0
            or spec.get("model_training_authorized") is not False
            or spec.get("network_eligible") is not False
            or spec.get("heldout_sealed") is not False):
        raise FreshTransferError("fake review claim or wrong research-only schema")
    rows=spec["cases"]
    if not isinstance(rows,list) or len(rows)!=3:
        raise FreshTransferError("exactly three unrelated public-project contexts required")
    prior_ids={a["id"] for a in prior.get("advisories",[])}
    train_rows=train["cases"]+inspected["cases"]
    old_repos={r["repository"].casefold() for r in train_rows}
    old_commits={r["commit"] for r in train_rows}
    old_ghsas={r["advisory"] for r in train_rows}
    seen=set()
    for row in rows:
        if not isinstance(row,dict) or set(row)!=CASE_FIELDS:
            raise FreshTransferError("fresh source row fields were changed")
        for field in ("id","repository","commit","parent","source_path","source_blob","test_path","test_blob"):
            if not isinstance(row[field],str) or not row[field]:
                raise FreshTransferError(f"missing source identity: {field}")
        if not re.fullmatch("[0-9a-f]{40}",row["commit"]) or not re.fullmatch("[0-9a-f]{40}",row["parent"]):
            raise FreshTransferError("commit or parent not pinned to 40-digit hash")
        if not all(re.fullmatch("[0-9a-f]{40}",row[k]) for k in ("source_blob","test_blob")):
            raise FreshTransferError("source and test Git blobs not pinned")
        ident=row["repository"].casefold()
        if ident in old_repos or ident in seen or row["commit"] in old_commits:
            raise FreshTransferError("source-project overlap with prior model research")
        seen.add(ident)
        if row["upstream_evidence"]!=f'https://github.com/{row["repository"]}/commit/{row["commit"]}':
            raise FreshTransferError("source provenance URL mismatches commit")
        if row["advisory"] is not None and (not re.fullmatch("GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}",row["advisory"]) or
                                             row["advisory"] in old_ghsas or row["advisory"] in prior_ids):
            raise FreshTransferError("advisory reused or malformed")
        if not isinstance(row["research_limitation"],str) or len(row["research_limitation"])<100:
            raise FreshTransferError("missing source-specific uncertainty")
        answers=[row.get("finding_answer"),row.get("conditional_answer")]
        if not all(isinstance(x,str) and 260<=len(x)<=920 for x in answers):
            raise FreshTransferError("missing substantive competing candidate")
        if not 0.72 <= len(answers[0].split())/len(answers[1].split())<=1.39:
            raise FreshTransferError("candidate length shortcut")
        if any(ADVISORY_ID.search(x) for x in answers):
            raise FreshTransferError("no advisory ID in candidate answers")
        contexts=row["scenarios"]
        if (not isinstance(contexts,list) or len(contexts)!=2
                or [x.get("id") for x in contexts]!=["exposure","missing-precondition"]
                or [x.get("proposed_preferred") for x in contexts]!=["finding","conditional"]
                or not all(set(x)=={"id","proposed_preferred","facts"} and
                           isinstance(x["facts"],str) and 140<=len(x["facts"])<=700
                           for x in contexts)):
            raise FreshTransferError("must include two opposing bounded hypothetical environments")
    return rows


def construct(spec: dict, train: dict, inspected: dict, prior: dict,
              commit_fetch: Callable[[str],dict]=fetch_github_commit,
              read_raw: Callable[[str],bytes]=fetch_raw) -> tuple[dict,dict]:
    rows=validate(spec,train,inspected,prior)
    public=[];private=[];verified=[]
    for row in rows:
        api=commit_fetch(f'https://api.github.com/repos/{row["repository"]}/commits/{row["commit"]}')
        if (api.get("sha")!=row["commit"]
                or [p.get("sha") for p in api.get("parents",[])]!=[row["parent"]]
                or api.get("html_url")!=row["upstream_evidence"]):
            raise FreshTransferError("wrong authentic upstream commit/parent")
        files={f["filename"]:f for f in api.get("files",[]) if isinstance(f,dict) and "filename" in f}
        selected={}
        for label,path,blob in (("source",row["source_path"],row["source_blob"]),
                                ("test",row["test_path"],row["test_blob"])):
            patch=_selected_patch(files.get(path),path,blob,row["id"],require_removed=(label=="source"))
            before=read_raw(raw_url(row["repository"],row["parent"],path))
            after=read_raw(raw_url(row["repository"],row["commit"],path))
            if git_blob_sha(after)!=blob or apply_patch(before,patch["patch"])!=after:
                raise FreshTransferError("exact pre/post source/test commit byte replay failed")
            selected[label]={"patch":patch["patch"],"before":before,
                             "old_blob":git_blob_sha(before),"new_blob":blob,
                             "source_patch_sha256":_hash(patch["patch"].encode())}
        windows=parent_regions(selected["source"]["before"],selected["source"]["patch"])
        window=max(windows,key=lambda x:(x["last_line"]-x["first_line"],x["first_line"]))
        language=LANGUAGES.get(Path(row["source_path"]).suffix)
        if language not in ("python","javascript"):
            raise FreshTransferError("unsupported source language in transfer probe")
        before_code=window["raw_source"]
        if ADVISORY_ID.search(before_code):
            raise FreshTransferError("pre-fix prompt contains advisory ID")
        source_prompt=("Review the following historical original code excerpt for a deployment-specific "
                       "security concern. Distinguish affected configurations from conditions not shown.\n\n"
                       "Source excerpt:\n"+FENCE+language+"\n"+before_code+FENCE)
        verified.append({"case_id":row["id"],"repository":row["repository"],
                         "parent_sha":row["parent"],"fix_sha":row["commit"],
                         "source_path":row["source_path"],"test_path":row["test_path"],
                         "parent_source_blob":selected["source"]["old_blob"],
                         "post_source_blob":selected["source"]["new_blob"],
                         "post_test_blob":selected["test"]["new_blob"],
                         "patch_source_sha256":selected["source"]["source_patch_sha256"],
                         "patch_test_sha256":selected["test"]["source_patch_sha256"],
                         "pre_fix_lines":[window["first_line"],window["last_line"]],
                         "pre_and_post_files_verified":2})
        for ctx in row["scenarios"]:
            case_id=row["id"]+":"+ctx["id"]
            question=source_prompt+"\n\nHypothetical deployment details:\n"+ctx["facts"]+"\n\nWhat conclusion does the actual evidence support for this case?"
            if len(question.encode())>4700:
                raise FreshTransferError("model task too long before tokenizer; do not silently truncate")
            positive=row["finding_answer"];negative=row["conditional_answer"]
            finding_first=bool(hashlib.sha256(case_id.encode()).digest()[0]&1)
            a,b=(positive,negative) if finding_first else (negative,positive)
            preferred=("A" if finding_first else "B") if ctx["proposed_preferred"]=="finding" else ("B" if finding_first else "A")
            public.append({"case_id":case_id,"question":question,"candidate_a":a,"candidate_b":b})
            private.append({"case_id":case_id,"source_project":row["repository"],
                            "ai_proposed_choice":preferred,"ai_proposed_kind":ctx["proposed_preferred"],
                            "human_approved":False,"training_eligible":False,
                            "independent_ground_truth":False})
    if len(public)!=6 or len(verified)!=3:
        raise FreshTransferError("missing real-source transfer tasks")
    out={"schema_version":1,"status":PUBLIC,"research_only":True,"network_eligible":False,
         "sealed_holdout":False,"independent_human_reviews":0,"training_authorized":False,
         "cases":public,"notice":"Original Git-pinned pre-fix code and invented deployment facts; no proposed preference exposed to scorer; publicly inspected AI draft, NOT independent accuracy."}
    key={"schema_version":1,"status":PRIVATE,"public_packet_sha256":_hash(canonical(out)),
         "source_specs_sha256":_hash(canonical(spec)),"research_only":True,
         "network_eligible":False,"independent_human_reviews":0,"training_authorized":False,
         "entries":private,"verified_sources":verified,
         "notice":"AI provisional answers and authentic post-fix/test provenance kept outside model questions; no independent human labels or network training permission."}
    return out,key


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Reproduce three brand-new public upstream security fix transfer cases")
    for name in ("spec","train-queue","old-queue","prior-advisories","public-out","key-out","token-out"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args(argv)
    paths=(a.spec,a.train_queue,a.old_queue,a.prior_advisories,a.public_out,a.key_out,a.token_out)
    try:
        if len({x.resolve() for x in paths})!=7 or any(x.exists() for x in (a.public_out,a.key_out,a.token_out)):
            raise FreshTransferError("refuse output overwrite or source alias")
        spec=json.loads(a.spec.read_text())
        train=load_queue(a.train_queue); old=load_queue(a.old_queue)
        prior=json.loads(a.prior_advisories.read_text())
        public,key=construct(spec,train,old,prior)
        from transformers import AutoTokenizer
        tok=AutoTokenizer.from_pretrained("answerdotai/ModernBERT-base")
        if not tok.is_fast:
            raise FreshTransferError("real fast ModernBERT tokenizer required")
        counts=[len(tok.encode(render(row["question"],row[col]),truncation=False))
                for row in public["cases"] for col in ("candidate_a","candidate_b")]
        if max(counts)>512:
            raise FreshTransferError("new real-source Task-plus-Answer exceeds hard 512-token node cap")
        audit={"schema_version":1,"status":"THREE_NEW_SOURCE_FULL_INPUTS_PASS_NODE_BUDGET",
               "source_projects_verified":3,"exact_pre_post_source_test_replays":6,
               "research_pairs":6,"real_full_model_inputs":len(counts),
               "max_full_input_tokens":max(counts),"node_cap":512,
               "source_packet_sha256":_hash(canonical(public)),
               "human_reviews":0,"network_eligible":False,"sealed_holdout":False}
        for dest in (a.public_out,a.key_out,a.token_out):
            dest.parent.mkdir(parents=True,exist_ok=True)
        a.public_out.write_bytes(canonical(public));a.key_out.write_bytes(canonical(key))
        a.token_out.write_bytes(canonical(audit))
        print(json.dumps(audit,indent=2))
        return 0
    except (FreshTransferError,ValueError,OSError,TypeError,KeyError,ImportError) as exc:
        p.exit(1,f"FALSUM FRESH SOURCE TRANSFER ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
