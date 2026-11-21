"""Phase 5U: four genuinely NEW repository-disjoint, authenticated public security-fix source pairs.

Eight original Git source files AND eight original upstream test files are
downloaded from four exact historical Git commits and each full Git blob SHA-1
checked BEFORE any local prompt construction or scoring. Public/open-book,
researcher-authored source-interpretation references: NOT expert gold, original
test execution, an independent new-model score, network ranking or adoption.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from .phase5p_raw_code_evaluator import _get_source
from .phase5l_pymdown_upstream_replay import git_blob
from .phase5m_real_source_sensitive_model import (
    ROOT, DiagnosticError, require, sha, read_json, canonical_json,
)

LOCK="data/phase5u-four-new-project-original-source-protocol.json"
LOCK_GIT_BLOB="ff1e9063f0f37e0a9265db25d6f767bb56db73e8"
ST_CHALLENGE="PHASE5U_ORIGINAL_GIT_AUTHENTICATED_FOUR_NEW_PROJECTS_PUBLIC_24_SOURCE_CONDITIONS"
ST_TEMPLATE="PHASE5U_UNFILLED_UNVERIFIED_EXTERNAL_CANDIDATE_RESPONSES"
ST_BASELINE="PHASE5U_DISCLOSED_PROMPT_ONLY_SOURCE_BLIND_SYNTHETIC_REFERENCE"
ST_PROOF="PHASE5U_FOUR_PROJECT_DISJOINT_ORIGINAL_SOURCE_AND_TEST_BLOB_AUTHENTICATION"
ST_SCORE="PHASE5U_UNVERIFIED_PUBLIC_CANDIDATE_RESPONSES_NOT_EXPERT_GOLD"
PROJECTS=("minimist-constructor","json5-proto-data",
          "tough-cookie-null-maps","follow-redirects-custom-headers")
REVISIONS=("parent","fixed","source-omitted")
POSITIONS=("original-order","swapped-order")
CHOICES=("A","B","ABSTAIN")
ALLOWED=("A","B","ABSTAIN","INVALID")
KNOWN_REPOS=(
    "minimistjs/minimist","json5/json5",
    "salesforce/tough-cookie","follow-redirects/follow-redirects",
)


def frozen(root:Path=ROOT)->dict:
    raw=(root/LOCK).read_bytes()
    require(git_blob(raw)==LOCK_GIT_BLOB,
            "Phase 5U source and prompt choices were altered after freeze")
    p=read_json(raw)
    require(p.get("schema_version")==1
            and p.get("status")==
                "PHASE5U_FOUR_PROJECT_DISJOINT_PUBLIC_UPSTREAM_SOURCE_SELECTION_FROZEN_BEFORE_MODEL_SCORING"
            and p.get("intent")=="SECURITY_REVIEW_GENERAL"
            and p.get("source_project_count")==4
            and p.get("new_historical_security_fix_count")==4
            and p.get("new_source_file_revision_count")==8
            and p.get("new_upstream_test_file_revision_count")==8
            and p.get("total_source_present_prompts")==16
            and p.get("total_source_omitted_controls")==8
            and p.get("total_prompts")==24
            and p.get("reference_distribution")=={"A":8,"B":8,"ABSTAIN":8}
            and p.get("source_blind_complete_four_way_upper_bound")==0
            and p.get("source_blind_prompt_only_maximum_matches")==16
            and p.get("original_source_git_blob_sha_verified_required") is True
            and p.get("original_source_test_file_sha_verified_required") is True
            and p.get("full_original_upstream_regression_tests_executed_by_this_stage") is False
            and p.get("actual_executed_source_behavior_not_claimed") is True
            and p.get("greedy_no_few_shot") is True
            and p.get("hidden_private_holdout") is False
            and p.get("model_pretraining_disjoint") is False
            and p.get("independent_appsec_gold_count")==0
            and p.get("no_live_miner_ranking_improvement_claim") is True
            and p.get("no_new_telegraph_network_registration") is True
            and p.get("no_telegraph_paid_requests") is True
            and p.get("no_independent_adoption_claim") is True
            and p.get("no_official_h2_entry_submitted") is True
            and p.get("max_model_input_tokens")==1024
            and p.get("max_generated_tokens")==12
            and p.get("frozen_model_system","").startswith("You are reviewing a claim")
            and p.get("frozen_model_user_template")==
                "Task: {question}\n\nOriginal source code excerpt:\n{code}\n\nA. {answer_a}\nB. {answer_b}\n\nAnswer with exactly A, B, or ABSTAIN.",
            "four-project source selection, prompt or no-gold contract drift")
    specs=p.get("cases")
    require(isinstance(specs,list) and len(specs)==4
            and tuple(x.get("key") for x in specs)==PROJECTS
            and tuple(x.get("repository") for x in specs)==KNOWN_REPOS
            and len({x.get("advisory") for x in specs})==4,
            "source project population is no longer disjoint")
    for x in specs:
        require(x.get("parent_commit")!=x.get("fixed_commit")
                and x.get("parent_source_blob")!=x.get("fixed_source_blob")
                and x.get("parent_test_blob")!=x.get("fixed_test_blob")
                and all(isinstance(x.get(k),str) and re.fullmatch(r"[a-f0-9]{40}",x[k])
                        for k in ("parent_commit","fixed_commit",
                                  "parent_source_blob","fixed_source_blob",
                                  "parent_test_blob","fixed_test_blob"))
                and all(isinstance(x.get(k),str) and x[k]
                        and len(x[k])<1000 for k in
                        ("source_path","test_path","question","answer_a","answer_b",
                         "parent_anchor","fixed_anchor","fixed_test_anchor"))
                and all(".." not in x[k] and not x[k].startswith("/") for k in
                        ("source_path","test_path"))
                and x.get("advisory","").startswith("GHSA-"),
                "original repository/commit/test file Git provenance malformed")
    return p


def ident(project:str,revision:str,position:str)->str:
    require(project in PROJECTS and revision in REVISIONS and position in POSITIONS,
            "unknown source condition or option presentation")
    return hashlib.sha256(("phase5u/authenticated/research/"+project+"/"+revision+
                           "/"+position).encode()).hexdigest()[:32]


def _load_git_file(case:dict,revision:str,kind:str,downloader)->tuple[str,str]:
    require(revision in ("parent","fixed") and kind in ("source","test"),
            "invalid original public asset role")
    repo=case["repository"]
    commit=case[revision+"_commit"]
    path=case[kind+"_path"]
    source="https://raw.githubusercontent.com/"+repo+"/"+commit+"/"+path
    raw=downloader(source)
    require(isinstance(raw,bytes) and 0<len(raw)<350000
            and git_blob(raw)==case[revision+"_"+kind+"_blob"],
            "original upstream source or test bytes changed or unverified")
    return raw.decode("utf-8","strict"),source


def _excerpt(source:str,anchor:str,extra:str|None=None)->str:
    lines=source.splitlines()
    hits=[i for i,s in enumerate(lines) if anchor in s]
    require(len(hits) in (1,2),"original source anchor missing or ambiguous")
    # Duplicate minimist/tough-cookie identical source guards exist in
    # separate functions. The first one is deterministically selected.
    pivot=hits[0]
    def segment(at:int,start:int,end:int):
        return "\n".join(lines[max(0,at+start):min(len(lines),at+end+1)])
    body=segment(pivot,-8,12)
    if extra:
        extra_hits=[i for i,s in enumerate(lines) if extra in s]
        require(len(extra_hits)==1,"original additional helper not unambiguous")
        body=(body+"\n\n// Separate verified excerpt from same original upstream file:\n"+
              segment(extra_hits[0],-4,8))
    require(45<len(body)<8000 and anchor in body and
            (not extra or extra in body),
            "original Git-verified source excerpt incomplete")
    return body


def challenge(*,root:Path=ROOT,downloader=_get_source)->tuple[dict,dict[str,str],dict]:
    p=frozen(root)
    rows=[]
    references={}
    source_proof=[]
    all_releases={}
    for case in p["cases"]:
        for revision in ("parent","fixed"):
            code,code_url=_load_git_file(case,revision,"source",downloader)
            test,test_url=_load_git_file(case,revision,"test",downloader)
            require(case[revision+"_anchor"] in code,
                    "frozen vulnerability source revision behavior anchor missing")
            if revision=="fixed":
                require(case["fixed_test_anchor"] in test,
                        "original upstream fixed regression test missing")
            cut=_excerpt(code,case[revision+"_anchor"],
                         case.get("fixed_extra_anchor") if revision=="fixed" else None)
            all_releases[(case["key"],revision)] = cut
            source_proof.append({
                "project":case["key"],
                "repository":case["repository"],
                "advisory_url":"https://github.com/advisories/"+case["advisory"],
                "release":revision,
                "source_git_commit":case[revision+"_commit"],
                "original_source_git_blob_sha1":case[revision+"_source_blob"],
                "original_upstream_test_git_blob_sha1":case[revision+"_test_blob"],
                "source_url":code_url,
                "original_upstream_test_url":test_url,
                "original_upstream_source_full_blob_sha_verified":True,
                "original_upstream_test_full_blob_sha_verified":True,
                "selected_code_excerpt_sha256":sha(cut.encode("utf-8")),
                "original_upstream_test_executed_by_phase5u":False,
                "security_claim_labels_researcher_derived":True,
            })
    for case in p["cases"]:
        for revision in REVISIONS:
            code=(all_releases[(case["key"],revision)]
                  if revision!="source-omitted" else
                  "[ORIGINAL SOURCE CODE OMITTED: no actual implementation supplied]")
            for position in POSITIONS:
                swap=position=="swapped-order"
                a=case["answer_b"] if swap else case["answer_a"]
                b=case["answer_a"] if swap else case["answer_b"]
                reference=("ABSTAIN" if revision=="source-omitted"
                           else ("A" if revision=="parent" else "B"))
                if swap and reference!="ABSTAIN":
                    reference="B" if reference=="A" else "A"
                user=(p["frozen_model_user_template"]
                      .replace("{question}",case["question"])
                      .replace("{code}",code)
                      .replace("{answer_a}",a).replace("{answer_b}",b))
                require(len(user)<12500
                        and all(s not in user for s in (
                            "{question}","{code}","{answer_a}","{answer_b}")),
                        "frozen model source excerpt or question substitution failed")
                key=ident(case["key"],revision,position)
                references[key]=reference
                rows.append({
                    "id":key,
                    # Caller must use ONLY messages for model input:
                    # no source Git revisions or role labels exposed.
                    "messages":[
                        {"role":"system","content":p["frozen_model_system"]},
                        {"role":"user","content":user},
                    ],
                    "prompt_sha256":sha(user.encode("utf-8")),
                })
    rows.sort(key=lambda x:sha(("falsum/phase5u/public-order/"+x["id"]).encode()))
    require(len(rows)==24 and len(set(references))==24
            and Counter(references.values())=={"A":8,"B":8,"ABSTAIN":8}
            and len(source_proof)==8,
            "new project-disjoint source challenge balance or provenance failed")
    public={
        "schema_version":1,"status":ST_CHALLENGE,
        "intent":"SECURITY_REVIEW_GENERAL",
        "original_frozen_project_selection_git_blob_sha1":LOCK_GIT_BLOB,
        "projects":list(PROJECTS),
        "new_distinct_public_project_count":4,
        "new_historical_security_fix_families":4,
        "original_code_git_blob_verified":8,
        "original_upstream_test_git_blob_verified":8,
        "actual_original_upstream_tests_executed":False,
        "source_present_conditions":16,
        "source_omitted_controls":8,
        "question_count":24,
        "response_classes_reference":{"A":8,"B":8,"ABSTAIN":8},
        "public_author_selected_not_blind":True,
        "candidate_model_scores_from_this_export":None,
        "independent_appsec_expert_gold":0,
        "network_ranking_changed":False,
        "network_evaluator_registered":False,
        "official_h2_entry_submitted":False,
        "questions":rows,
    }
    proof={
        "schema_version":1,"status":ST_PROOF,
        "original_selection_git_blob_sha1":LOCK_GIT_BLOB,
        "new_projects":4,"new_historical_fixes":4,
        "original_upstream_source_git_verified":8,
        "original_upstream_test_git_verified":8,
        "original_upstream_tests_actually_executed":False,
        "actual_model_inference":False,
        "independent_appsec_gold":0,
        "network_evaluator_registered":False,
        "original_immutable_project_git_files":source_proof,
    }
    return public,references,proof


def template(doc:dict)->dict:
    return {"schema_version":1,"status":ST_TEMPLATE,
            "challenge_sha256":sha(canonical_json(doc)),
            "decisions":[{"id":q["id"],"choice":None} for q in doc["questions"]]}


def baseline()->dict[str,str]:
    return {ident(project,revision,order):
            ("ABSTAIN" if revision=="source-omitted" else "A")
            for project in PROJECTS for revision in REVISIONS for order in POSITIONS}


def score(references:dict[str,str],predictions:dict[str,str],*,origin:str)->dict:
    require(origin in ("DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL",
                       "UNVERIFIED_EXTERNAL_PUBLIC_CANDIDATE"),
            "cannot forge human gold or real model inference provenance")
    require(len(references)==24 and set(predictions)==set(references)
            and Counter(references.values())=={"A":8,"B":8,"ABSTAIN":8}
            and all(x in ALLOWED for x in predictions.values()),
            "candidate response missing or out of scope")
    matched=sum(references[k]==predictions[k] for k in references)
    details={}
    fourway=0
    present=0
    missing=0
    for project in PROJECTS:
        pairs=[ident(project,rev,pos) for rev in ("parent","fixed") for pos in POSITIONS]
        abst=[ident(project,"source-omitted",pos) for pos in POSITIONS]
        four=int(all(predictions[x]==references[x] for x in pairs))
        fourway+=four
        present+=sum(predictions[x]==references[x] for x in pairs)
        missing+=sum(predictions[x]==references[x] for x in abst)
        details[project]={
            "four_way_source_and_position_correct":bool(four),
            "code_present_correct":sum(predictions[x]==references[x] for x in pairs),
            "code_missing_abstain_correct":sum(predictions[x]==references[x] for x in abst),
        }
    return {
        "schema_version":1,"origin":origin,
        "total_public_new_project_source_conditions":24,
        "authenticated_original_historical_fix_projects":4,
        "genuine_new_distinct_vulnerability_families":4,
        "source_present_matches":present,
        "source_absent_correct_abstention":missing,
        "matches_to_researcher_derived_public_references":matched,
        "complete_correct_four_way_source_and_answer_reversals":fourway,
        "prompt_only_source_hidden_maximum_matches":16,
        "prompt_only_source_hidden_maximum_complete_four_way":0,
        "public_lookup_attacker_not_excluded":True,
        "old_upstream_tests_not_rerun":True,
        "new_model_inference_verified":False,
        "independent_appsec_gold":0,
        "real_telegraph_miner_ranking_changed":False,
        "registered_network_evaluator":False,
        "new_h2_submission":False,
        "project_details":details,
    }


def validated_candidate(challenge:dict,value:dict)->dict[str,str]:
    require(isinstance(value,dict)
            and set(value)=={"schema_version","status","challenge_sha256","decisions"}
            and type(value["schema_version"]) is int and value["schema_version"]==1
            and value["status"]==ST_TEMPLATE
            and value["challenge_sha256"]==sha(canonical_json(challenge))
            and isinstance(value["decisions"],list)
            and len(value["decisions"])==24,
            "submitted response does not match exact original Git source challenge")
    answers={}
    for expected,choice in zip(challenge["questions"],value["decisions"]):
        require(isinstance(choice,dict)
                and set(choice)=={"id","choice"}
                and choice["id"]==expected["id"]
                and choice["choice"] in CHOICES,
                "unknown, malformed, incomplete, duplicate or reordered response")
        answers[choice["id"]]=choice["choice"]
    require(len(answers)==24,"duplicate response ID in submission")
    return answers


def _write(path:Path,contents:dict)->None:
    require(not path.exists() and not path.is_symlink() and
            path.suffix==".json","original source result must be fresh write-once JSON")
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("x",encoding="utf-8") as f:
        json.dump(contents,f,indent=2,sort_keys=True,ensure_ascii=False)
        f.write("\n")


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Four new Git-authenticated public security-fix projects, not independent AppSec gold")
    modes=parser.add_subparsers(dest="mode",required=True)
    exp=modes.add_parser("export")
    exp.add_argument("--questions-out",type=Path,required=True)
    exp.add_argument("--template-out",type=Path,required=True)
    exp.add_argument("--source-proof-out",type=Path,required=True)
    bas=modes.add_parser("baseline")
    bas.add_argument("--out",type=Path,required=True)
    sc=modes.add_parser("score")
    sc.add_argument("--questions",type=Path,required=True)
    sc.add_argument("--predictions",type=Path,required=True)
    sc.add_argument("--out",type=Path,required=True)
    a=parser.parse_args(argv)
    try:
        doc,answers,proof=challenge()
        if a.mode=="export":
            paths=[a.questions_out,a.template_out,a.source_proof_out]
            require(len(set(paths))==3 and not any(p.exists() for p in paths),
                    "source proof and exported challenge outputs must be distinct write-once")
            _write(a.questions_out,doc)
            _write(a.template_out,template(doc))
            _write(a.source_proof_out,proof)
            print(json.dumps({"original_git_source_files_verified":8,
                "original_git_upstream_tests_verified":8,
                "new_security_fix_projects":4,
                "new_source_conditions":24,
                "source_blind_full_reversal_bound":0,
                "expert_gold":0},sort_keys=True))
            return 0
        if a.mode=="baseline":
            out={"schema_version":1,"status":ST_BASELINE,
                 "original_source_files_verified_before_scoring":True,
                 "source_code_read_by_synthetic_baseline":False,
                 "real_model_inference":False,
                 "score":score(answers,baseline(),
                               origin="DISCLOSED_SYNTHETIC_PROMPT_ONLY_CONTROL")}
        else:
            require(read_json(a.questions.read_bytes())==doc,
                    "submitted challenge does not match original full Git source and test bytes")
            selected=validated_candidate(doc,read_json(a.predictions.read_bytes()))
            out={"schema_version":1,"status":ST_SCORE,
                 "candidate_identity_or_independence_verified":False,
                 "source_files_fully_git_verified":True,
                 "original_upstream_tests_executed":False,
                 "score":score(answers,selected,
                               origin="UNVERIFIED_EXTERNAL_PUBLIC_CANDIDATE")}
        _write(a.out,out)
        print(json.dumps({"mode":a.mode,"status":out["status"],
            "matches":out["score"]["matches_to_researcher_derived_public_references"],
            "full_source_and_answer_order_reversals":out["score"]["complete_correct_four_way_source_and_answer_reversals"],
            "not_independent_gold":True},sort_keys=True))
        return 0
    except (OSError,UnicodeError,ValueError,KeyError,TypeError,AssertionError,
            DiagnosticError) as exc:
        parser.exit(1,"PHASE5U ORIGINAL GIT SOURCE CONTRACT FAILED CLOSED: "+
                    str(exc)[:280]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
