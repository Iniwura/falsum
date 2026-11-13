"""Phase 4H: genuine unchanged Telegraph Foundation scorer on four precommitted projects.

Eight source-revision factual conditions, sixteen real official score inputs,
thirty-two repeated inference calls, no blind holdout, no expert gold labels,
no trained improvement and no network registration. Any score packet that cannot
pass the official score manifest/f32 audit FAILS CLOSED.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from .phase3c_score_inputs import TOKENIZER_SHA256
from .phase3c_score_report import _score, ScoreProofError, MODEL_SHA, FOUNDATION_SHA
from .phase3y_hard_model_probe import render
from .phase4h_frozen_source import (
    STATUS as SOURCE_STATUS, validate_lock, LOCK_GIT_BLOB
)

INPUT_STATUS = "PHASE4H_FROZEN_EIGHT_NEW_REPO_SOURCE_CONDITIONS_OFFICIAL_INPUTS"
REPORT_STATUS = "PHASE4H_REAL_ORIGINAL_QUARANTINED_LORA_NEW_PROJECTS_NOT_NETWORK_QUALITY"
TOKEN_CAP = 256
SAFE_ID = re.compile(r"^[a-z][a-z0-9-]+--[AB]$")


class ProbeError(ValueError):
    pass


def require(ok: bool, reason: str):
    if not ok:
        raise ProbeError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(text: str) -> str:
    return sha(text.encode("utf-8"))


def load_source(lock_raw: bytes, source_raw: bytes) -> tuple[dict, dict, list[dict]]:
    manifest = validate_lock(lock_raw)
    source = json.loads(source_raw)
    require(isinstance(source, dict)
            and source.get("schema_version") == 1
            and source.get("status") == SOURCE_STATUS
            and source.get("frozen_selection_git_blob") == LOCK_GIT_BLOB
            and source.get("frozen_selection_sha256") == sha(lock_raw)
            and source.get("source_repositories_verified") == 4
            and source.get("source_revision_conditions") == 8
            and source.get("source_parent_and_fix_file_blob_checks") == 16
            and source.get("source_patches_verified") == 4
            and source.get("selected_test_files_changed_in_fix") == 2
            and source.get("selected_test_files_unchanged_in_fix") == 2
            and source.get("commits_real_and_parent_verified") is True
            and source.get("downloaded_public_patches_executed") is False
            and source.get("independent_appsec_gold_labels") == 0
            and source.get("new_eligible_anjoman_rows") == 0
            and source.get("registered_evaluator") is False
            and source.get("model_scores_observed") is False
            and source.get("public_new_to_repo_not_blind_or_pretraining_disjoint") is True,
            "real source verification report is missing or falsely promoted")
    provenances = source.get("projects")
    require(isinstance(provenances,list) and len(provenances) == 4,
            "four exact source-verified upstream cases required")
    for row, verified in zip(manifest["cases"], provenances):
        require(verified.get("project") == row["key"]
                and verified.get("upstream_repository") == row["repository"]
                and verified.get("fix_commit") == row["fixed"]
                and verified.get("direct_parent_commit") == row["parent"]
                and verified.get("source_file_modified_in_pinned_fix") is True
                and verified.get("selected_test_file_modified_in_pinned_fix")
                    is row["test_changed_in_fix"]
                and verified.get("source_before_and_after_anchor_verified") is True
                and verified.get("test_added_anchor_verified")
                    is (row["test_added_anchor"] is not None),
                "source-verified project identity or patch claim does not agree")
        blobs = verified.get("source_and_test_blobs")
        require(isinstance(blobs,dict) and len(blobs) == 4,
                "source/test parent/fix blob proof absent")
        for revision in ("parent","fixed"):
            for kind in ("source","test"):
                name=revision+"_"+kind
                blob=blobs.get(name)
                require(isinstance(blob,dict)
                        and blob.get("pinned_git_blob_sha1") == row[name+"_blob"]
                        and re.fullmatch(r"[a-f0-9]{64}",blob.get("downloaded_bytes_sha256",""))
                        and isinstance(blob.get("bytes"),int) and blob["bytes"] > 0,
                        "inconsistent source blob identity")
    cases=[]
    for row in manifest["cases"]:
        for revision,expected in (("parent","A"),("fixed","B")):
            cases.append({
                "case_id":row["key"]+"-"+revision,
                "project":row["key"],
                "source_revision":revision,
                "exact_commit_sha":row[revision],
                "question":row["question_before"] if revision=="parent" else row["question_after"],
                "answers":[{"id":"A","text":row["a"]},{"id":"B","text":row["b"]}],
                "source_based_author_expected":expected,
                "independent_appsec_gold":None,
            })
    require(len(cases)==8
            and [c["source_based_author_expected"] for c in cases] == ["A","B"]*4
            and len({c["case_id"] for c in cases})==8,
            "expected four frozen contextual changes and balanced author answers")
    return manifest,source,cases


def score_key(case_id:str, label:str)->str:
    ident=case_id+"--"+label
    require(SAFE_ID.fullmatch(ident) is not None, "unsafe official score packet path")
    return ident


def make_inputs(lock_raw:bytes, source_raw:bytes, tokenizer_raw:bytes, encode)->dict:
    manifest,_,cases=load_source(lock_raw,source_raw)
    require(sha(tokenizer_raw) == TOKENIZER_SHA256, "tokenizer is not pinned official Foundation tokenizer")
    entries=[]
    for case in cases:
        for answer in case["answers"]:
            prompt=render(case["question"],answer["text"])
            ids=encode(prompt)
            require(isinstance(ids,list) and 8<=len(ids)<=TOKEN_CAP
                    and ids[0] == 50281 and ids[-1]==50282
                    and all(type(v) is int and 0<=v<50368 for v in ids),
                    "official tokenizer invalid or >256-token budget, no truncation")
            entries.append({
                "id":score_key(case["case_id"],answer["id"]),
                "case_id":case["case_id"],
                "answer_id":answer["id"],
                "exact_source_commit":case["exact_commit_sha"],
                "question_sha256":digest(case["question"]),
                "answer_sha256":digest(answer["text"]),
                "rendered_sha256":digest(prompt),
                "input_ids":ids,"token_count":len(ids),
                "source_author_expected":case["source_based_author_expected"],
                "independent_appsec_adjudicated":False,
            })
    require(len(entries)==16 and len({r["id"] for r in entries})==16,
            "not sixteen distinct scored answer requests")
    return {
        "schema_version":1,"status":INPUT_STATUS,
        "frozen_lock_git_blob":LOCK_GIT_BLOB,
        "frozen_manifest_sha256":sha(lock_raw),
        "real_verified_source_sha256":sha(source_raw),
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "intent":"SECURITY_REVIEW_GENERAL","intent_family":"SECURITY_REVIEW",
        "source_projects":4,"source_conditions":8,"model_inputs":16,
        "not_blind_or_pretraining_disjoint":True,
        "source_author_hypotheses_not_independent_labels":True,
        "independent_appsec_gold_labels":0,"training_allowed":False,
        "registered_evaluator":False,
        "inputs":entries,
    }


def audit(lock_raw:bytes, source_raw:bytes, frozen:dict, packets:dict)->dict:
    manifest,source,cases=load_source(lock_raw,source_raw)
    require(isinstance(frozen,dict)
            and frozen.get("status")==INPUT_STATUS
            and frozen.get("schema_version")==1
            and frozen.get("frozen_lock_git_blob")==LOCK_GIT_BLOB
            and frozen.get("frozen_manifest_sha256")==sha(lock_raw)
            and frozen.get("real_verified_source_sha256")==sha(source_raw)
            and frozen.get("official_tokenizer_sha256")==TOKENIZER_SHA256
            and frozen.get("intent")=="SECURITY_REVIEW_GENERAL"
            and frozen.get("intent_family")=="SECURITY_REVIEW"
            and frozen.get("source_projects")==4
            and frozen.get("source_conditions")==8
            and frozen.get("model_inputs")==16
            and frozen.get("not_blind_or_pretraining_disjoint") is True
            and frozen.get("source_author_hypotheses_not_independent_labels") is True
            and frozen.get("independent_appsec_gold_labels")==0
            and frozen.get("training_allowed") is False
            and frozen.get("registered_evaluator") is False,
            "frozen token input provenance or no-release contract altered")
    source_inputs=frozen.get("inputs")
    require(isinstance(source_inputs,list) and len(source_inputs)==16
            and isinstance(packets,dict) and len(packets)==16,
            "missing/extra token inputs or genuine score packets")
    intended={(case["case_id"],ans["id"]): (case,ans)
              for case in cases for ans in case["answers"]}
    require(set(packets)=={score_key(c,a) for c,a in intended},
            "not exactly the score packet IDs committed in frozen cases")
    results,score_hex={},{}
    for row in source_inputs:
        require(isinstance(row,dict), "not a real tokenizer input")
        case,ans=intended.get((row.get("case_id"),row.get("answer_id")),(None,None))
        require(case is not None and ans is not None,"unknown or injected scoring candidate")
        ident=score_key(case["case_id"],ans["id"])
        task=render(case["question"],ans["text"])
        ids=row.get("input_ids")
        require(row.get("id")==ident
                and row.get("exact_source_commit")==case["exact_commit_sha"]
                and row.get("question_sha256")==digest(case["question"])
                and row.get("answer_sha256")==digest(ans["text"])
                and row.get("rendered_sha256")==digest(task)
                and row.get("source_author_expected")==case["source_based_author_expected"]
                and row.get("independent_appsec_adjudicated") is False
                and isinstance(ids,list)
                and type(row.get("token_count")) is int
                and len(ids)==row["token_count"]
                and 8<=len(ids)<=TOKEN_CAP
                and ids[0]==50281 and ids[-1]==50282
                and all(type(v) is int and 0<=v<50368 for v in ids),
                "source-to-token/f32 score identity mismatch")
        require(ident not in results, "duplicate score input")
        checked=_score(packets[ident],ident)
        results[ident]=checked["float32_value"]
        score_hex[ident]=checked["float32_score_hex"]
    require(len(results)==16,"missing unique actual signed score inputs")
    comparisons=[]
    for case in cases:
        a=results[score_key(case["case_id"],"A")]
        b=results[score_key(case["case_id"],"B")]
        selected="A" if a>b else "B" if b>a else "TIE"
        comparisons.append({
            "case_id":case["case_id"],"source_project":case["project"],
            "source_revision":case["source_revision"],
            "source_based_author_expectation":case["source_based_author_expected"],
            "model_preferred":selected,"score_margin_a_minus_b":a-b,
            "matches_source_author_hypothesis":selected==case["source_based_author_expected"],
        })
    reversals=[]
    for i in range(0,8,2):
        pre,post=comparisons[i:i+2]
        require(pre["source_project"]==post["source_project"]
                and pre["source_revision"]=="parent"
                and post["source_revision"]=="fixed",
                "mispaired patch contexts")
        reversals.append({
            "source_project":pre["source_project"],
            "expected_source_fact_change":"A_TO_B",
            "actual_model_choice_change":pre["model_preferred"]!=post["model_preferred"]
                and "TIE" not in (pre["model_preferred"],post["model_preferred"]),
            "both_research_author_conditions_match":pre["matches_source_author_hypothesis"]
                and post["matches_source_author_hypothesis"]
        })
    return {
        "schema_version":1,"status":REPORT_STATUS,
        "actual_official_foundation_inference":True,
        "original_quarantined_lora_sha256":MODEL_SHA,
        "official_foundation_sha256":FOUNDATION_SHA,
        "official_tokenizer_sha256":TOKENIZER_SHA256,
        "frozen_lock_git_blob":LOCK_GIT_BLOB,
        "frozen_selection_sha256":sha(lock_raw),
        "real_source_verification_sha256":sha(source_raw),
        "frozen_token_inputs_sha256":sha(json.dumps(frozen,sort_keys=True,separators=(",",":")).encode()),
        "true_official_score_inputs":16,
        "two_inferences_per_input":True,
        "actual_repeated_inference_calls":32,
        "four_new_repo_source_comparisons":8,
        "source_fact_pair_reversals":4,
        "source_author_agreements":sum(x["matches_source_author_hypothesis"] for x in comparisons),
        "complete_author_source_fact_reversals":sum(x["both_research_author_conditions_match"] for x in reversals),
        "model_preference_reversal_count":sum(x["actual_model_choice_change"] for x in reversals),
        "constant_A_baseline_matches":4,
        "constant_B_baseline_matches":4,
        "source_comparisons":comparisons,"revision_groups":reversals,
        "actual_score_hex_by_input":score_hex,
        "not_independently_expert_adjudicated":True,
        "independent_appsec_gold_labels":0,
        "not_blind_or_pretraining_disjoint":True,
        "no_new_eligible_anjoman_rows":True,
        "no_training_or_model_improvement_performed":True,
        "registered_evaluator":False,
        "automatic_registration_permitted":False,
        "model_release_veto":True,
        "network_accuracy_certified":False,
        "warning":"Authentic old LoRA on eight new-to-FALSUM public source-version conditions. Mechanical source interpretation is researcher-provisional, not independent expert judgments or a sealed holdout. A green real-run CI means inference integrity only; exact negative model outcomes remain public."
    }


def main(argv=None)->int:
    parser=argparse.ArgumentParser(description="Score old Telegraph Foundation LoRA only; research never model approval")
    parser.add_argument("--lock",type=Path,required=True)
    parser.add_argument("--source-report",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--tokenizer",type=Path)
    parser.add_argument("--inputs",type=Path)
    parser.add_argument("--scores-dir",type=Path)
    args=parser.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink(),"do not overwrite actual scoring evidence")
        lock_raw=args.lock.read_bytes()
        source_raw=args.source_report.read_bytes()
        if args.tokenizer and args.inputs is None and args.scores_dir is None:
            from tokenizers import Tokenizer
            tokenizer_bytes=args.tokenizer.read_bytes()
            tokenizer=Tokenizer.from_str(tokenizer_bytes.decode("utf-8"))
            result=make_inputs(lock_raw,source_raw,tokenizer_bytes,
                lambda s: tokenizer.encode(s,add_special_tokens=True).ids)
            score_inputs=[]
            for row in result["inputs"]:
                pth=args.out.parent/("SCORE-"+row["id"]+".json")
                require(not pth.exists() and not pth.is_symlink(),"score packet output exists")
                score_inputs.append((pth,{"input_ids":row["input_ids"],
                                          "attention_mask":[1]*row["token_count"]}))
            args.out.parent.mkdir(parents=True,exist_ok=True)
            for pth,ids in score_inputs:
                pth.write_text(json.dumps(ids,separators=(",",":"))+"\n",encoding="utf-8")
        elif args.inputs and args.scores_dir and args.tokenizer is None:
            frozen=json.loads(args.inputs.read_text(encoding="utf-8"))
            require(isinstance(frozen,dict) and isinstance(frozen.get("inputs"),list),
                    "real frozen inputs missing")
            packets={}
            for entry in frozen["inputs"]:
                ident=entry.get("id")
                require(isinstance(ident,str) and SAFE_ID.fullmatch(ident) is not None
                        and ident not in packets,"invalid/duplicate scoring path")
                packets[ident]=json.loads(
                    (args.scores_dir/ident/"OFFICIAL-SCORE.json").read_text())
            result=audit(lock_raw,source_raw,frozen,packets)
        else:
            raise ProbeError("pass exactly --tokenizer OR --inputs with --scores-dir")
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        print(json.dumps({k:result[k] for k in (
            ("status","true_official_score_inputs","source_author_agreements",
             "complete_author_source_fact_reversals","model_release_veto")
            if args.inputs else ("status","model_inputs","source_conditions","training_allowed"))},indent=2))
        return 0
    except (ValueError,KeyError,TypeError,IndexError,OSError,UnicodeError,ScoreProofError) as e:
        parser.exit(1,"PHASE4H GENUINE SCORE REJECTED: "+str(e)+"\n")


if __name__=="__main__":
    raise SystemExit(main())
