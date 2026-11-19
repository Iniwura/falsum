"""Source-test witness checker for *structured* security-review claims.

Every eligible fact is tied to a real public upstream parent/fix test outcome:
original genuine suite PASS; exact NEW security test FAILS on vulnerable parent
for the expected assertion; identical new security test PASSES on the fix.
Outputs SUPPORTED/CONTRADICTED/ABSTAIN for *precisely typed* review claims.

This DOES NOT parse freeform natural-language review, validate production
exploitability, supply independent AppSec gold labels, train a neural judge,
register an Anjoman scorer or submit any private material. Constructed
self-test agreement is by construction, not a model accuracy estimate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re

from .phase4p_open_source_review import load_lock
from .phase4t_four_stage_evidence import EXPECTED_IDS, EXPECTED_RUNS

SOURCE_SHA256 = "957796c514970d1b92ac930d423757daf10826e0c83f4d993544550cec7010c7"
MANIFEST_SHA256 = "52ca4510e5e56a541e53726923fd489bf29cf37fe78e56958dcea3f6cf4e6436"
ORIGINAL_FOUR_STAGE_PROOF_SHA256 = "e033e98fe8649f9b27a53f4e0f183bfc086257dc87f15ead0ba060aabf4fbf1c"
EXPECTED_RECEIPTS = {
    "koa-redirect": ("koajs/koa","origin-check-guard",44352329150,
                     "a44fefd30362a794e1002001d234cfaf065b2f5e2b813cc4f01fc62425bfd9cb"),
    "hono-csrf": ("honojs/hono","text-ping-csrf-content-type",44352329150,
                  "7ed8b2407133ec620dee5510533af0782006a31766d520ef8f8ee916aa71fffe"),
    "langchain-path": ("langchain-ai/langchain","initial-default-path-validation",44353999011,
                       "14b82e58c12264aea9eb743c2659d27cbdf72110ab0a907a974a4b3822dc98f8"),
    "langchain-symlink": ("langchain-ai/langchain","followup-resolved-symlink-suffix",44353999011,
                          "c2fe815535477749df1243f43bc6af98198a157fd76a1673922abc1b2fb8b5e3"),
}
STATUS = "FALSUM_SOURCE_WITNESS_TYPED_CLAIM_CHECKER_OFFLINE_NOT_NETWORK_ADAPTER"
EVIDENCE_STATUS = "PHASE4U_DERIVED_PERMANENT_INDEX_FROM_AUTHENTICATED_FOUR_STAGE_ACTIONS_NOT_GOLD"
CLAIMS = (
    "UPSTREAM_REGRESSION_PASSES",
    "UPSTREAM_REGRESSION_FAILS",
    "CONFIRMED_PRODUCTION_EXPLOIT",
    "GUARANTEED_UNIVERSAL_APPLICATION_SAFETY",
)
RESULTS = ("SUPPORTED", "CONTRADICTED", "ABSTAIN")
MAX_REQUESTS = 120
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class SourceWitnessError(ValueError):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SourceWitnessError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(path: Path, maximum: int=80_000) -> bytes:
    require(path.is_file() and not path.is_symlink(),
            "missing or symlinked evidence request file")
    require(0 < path.stat().st_size <= maximum,
            "invalid or oversized evidence request file")
    return path.read_bytes()


def validated_index(index_raw: bytes, lock_raw: bytes) -> dict:
    require(isinstance(index_raw,bytes) and 0<len(index_raw)<=30_000,
            "evidence must be bounded JSON bytes")
    require(sha(lock_raw)==SOURCE_SHA256, "source selection does not match authenticated real source proof")
    lock=load_lock(lock_raw)
    try:
        data=json.loads(index_raw)
    except (ValueError,UnicodeError) as exc:
        raise SourceWitnessError("evidence index is not JSON") from exc
    require(isinstance(data,dict) and
            data.get("schema_version")==1 and
            data.get("status")==EVIDENCE_STATUS,
            "unapproved or missing permanent source-execution index")
    require(set(data)=={
        "schema_version","status","source_run","original_run_ids","counts",
        "assertions","receipts"
    }, "permanent source index has unexpected private or unapproved fields")
    orig=data.get("source_run",{})
    require(isinstance(orig,dict) and
            orig.get("original_unmodified_extracted_json_sha256") ==
            ORIGINAL_FOUR_STAGE_PROOF_SHA256 and
            orig.get("source_selection_sha256")==SOURCE_SHA256 and
            orig.get("source_run_manifest_sha256")==MANIFEST_SHA256 and
            orig.get("artifact_id")==14452826588 and
            orig.get("url")=="https://github.com/Iniwura/falsum/actions/runs/44356563508" and
            orig.get("extracted_json_is_not_stored_verbatim_here") is True,
            "permanent index has incorrect original GitHub Actions run provenance")
    require(data.get("original_run_ids")==[
        EXPECTED_RUNS["phase4r"], EXPECTED_RUNS["phase4s"]
    ], "source execution receipt runs changed")
    counts=data.get("counts",{})
    require(isinstance(counts,dict)
            and counts.get("distinct_repositories")==3
            and counts.get("upstream_historical_patches")==4
            and counts.get("source_review_questions")==6
            and counts.get("real_execution_original_pass_new_parent_test_fail_fixed_test_pass")==4,
            "upstream source execution counts not authenticated")
    limits=data.get("assertions",{})
    require(isinstance(limits,dict),"malformed source-only proof limits")
    require(limits.get("independent_expert_gold_labels")==0
            and limits.get("new_anjoman_eligible_rows")==0
            and limits.get("trained_model_improvement_proven") is False
            and limits.get("registered_evaluator") is False
            and limits.get("real_deployment_exploitability_proven") is False
            and limits.get("official_h2_submitted") is False,
            "source-only evidence misrepresented as model validation")
    records=data.get("receipts")
    require(isinstance(records,list) and len(records)==4
            and tuple(x.get("id") for x in records)==EXPECTED_IDS,
            "expected four immutable executed source witnesses not found")
    index={}
    for entry in records:
        require(isinstance(entry,dict) and set(entry)=={
            "id","repository","stage","original_git_commit","fixed_git_commit",
            "original_source_git_blob","fixed_source_git_blob",
            "same_fixed_upstream_regression_test_git_blob",
            "raw_source_runtime_receipt_sha256","run_url",
            "original_upstream_test_passed",
            "original_source_with_fixed_security_regression_failed_expected_assertion",
            "fixed_source_with_same_regression_passed","independent_human_gold"
        }, "unapproved source witness record fields")
        require(entry["id"] in EXPECTED_RECEIPTS,
                "source witness case not in four authenticated runs")
        repo,stage_name,run_id,receipt_sha=EXPECTED_RECEIPTS[entry["id"]]
        require(entry["repository"]==repo and entry["stage"]==stage_name
                and entry["run_url"]==
                f"https://github.com/Iniwura/falsum/actions/runs/{run_id}"
                and entry["raw_source_runtime_receipt_sha256"]==receipt_sha,
                "source witness original GitHub execution SHA or case identity changed")
        matches=[r for r in lock["cases"] if r["repository"]==entry["repository"]]
        require(len(matches)==1, "source-execution case from unverified repository")
        row=matches[0]
        stages=[s for s in row["patches"] if s["stage"]==entry["stage"]]
        require(len(stages)==1, "noncanonical source fix stage")
        stage=stages[0]
        for k,expected in {
            "original_git_commit":stage["parent"],
            "fixed_git_commit":stage["fix"],
            "original_source_git_blob":stage["parent_source_blob"],
            "fixed_source_git_blob":stage["fixed_source_blob"],
            "same_fixed_upstream_regression_test_git_blob":stage["fixed_test_blob"],
        }.items():
            require(entry.get(k)==expected, "tampered source/fix/test Git byte witness")
        require(isinstance(entry.get("raw_source_runtime_receipt_sha256"),str)
                and HEX64.fullmatch(entry["raw_source_runtime_receipt_sha256"]) is not None
                and entry.get("run_url") in (
                    "https://github.com/Iniwura/falsum/actions/runs/44352329150",
                    "https://github.com/Iniwura/falsum/actions/runs/44353999011"),
                "missing or noncanonical original run log SHA proof")
        require(entry.get("original_upstream_test_passed") is True
                and entry.get("original_source_with_fixed_security_regression_failed_expected_assertion") is True
                and entry.get("fixed_source_with_same_regression_passed") is True
                and entry.get("independent_human_gold") is False,
                "original source-fix negative/positive controls not preserved")
        index[entry["id"]]=entry
    return index


def canonical_claim(witness: dict, revision: str, claim_type: str) -> dict:
    require(revision in ("parent","fixed"), "invalid Git revision role")
    require(claim_type in CLAIMS, "unknown schema claim type")
    commit=(witness["original_git_commit"] if revision=="parent"
            else witness["fixed_git_commit"])
    source=(witness["original_source_git_blob"] if revision=="parent"
            else witness["fixed_source_git_blob"])
    return {
        "case_id":witness["id"],
        "upstream_commit":commit,
        "claim_type":claim_type,
        "evidence":{
            "source_blob_sha1":source,
            "new_security_regression_test_blob_sha1":witness["same_fixed_upstream_regression_test_git_blob"],
            "actual_execution_receipt_sha256":witness["raw_source_runtime_receipt_sha256"],
        },
    }


def evaluate(index:dict, claim:dict) -> dict:
    require(isinstance(claim,dict) and set(claim)=={
        "case_id","upstream_commit","claim_type","evidence"
    }, "claim must be exact structured source witness schema")
    require(isinstance(claim["case_id"],str) and
            1<=len(claim["case_id"])<=96 and
            isinstance(claim["upstream_commit"],str) and
            1<=len(claim["upstream_commit"])<=100 and
            isinstance(claim["claim_type"],str) and
            1<=len(claim["claim_type"])<=100 and
            isinstance(claim["evidence"],dict) and
            set(claim["evidence"])=={
                "source_blob_sha1",
                "new_security_regression_test_blob_sha1",
                "actual_execution_receipt_sha256",
            }, "malformed source/test proof declaration")
    result={
        "case_id":claim["case_id"],
        "upstream_commit":claim["upstream_commit"],
        "claim_type":claim["claim_type"],
        "verdict":"ABSTAIN",
        "reason":"SOURCE_OR_ASSERTION_NOT_VERIFIED",
        "truth_basis":"AUTHENTICATED_PUBLIC_UPSTREAM_GIT_REGRESSION_RUNS_ONLY",
        "not_freeform_natural_language_scoring":True,
        "not_independent_appsec_gold":True,
        "not_network_eligible":True,
        "trained_model_accuracy_measurement":False,
        "production_exploitability_assessed":False,
    }
    witness=index.get(claim["case_id"])
    if witness is None:
        return result
    commit=claim["upstream_commit"]
    if commit==witness["original_git_commit"]:
        revision="parent"
        source=witness["original_source_git_blob"]
    elif commit==witness["fixed_git_commit"]:
        revision="fixed"
        source=witness["fixed_source_git_blob"]
    else:
        result["reason"]="UNSUPPORTED_GIT_REVISION"
        return result
    evidence=claim["evidence"]
    if not all(isinstance(value,str) and len(value)<=80
               for value in evidence.values()):
        result["reason"]="MALFORMED_OR_MISSING_PRIMARY_EVIDENCE"
        return result
    if (evidence.get("source_blob_sha1")!=source
            or evidence.get("new_security_regression_test_blob_sha1") !=
            witness["same_fixed_upstream_regression_test_git_blob"]
            or evidence.get("actual_execution_receipt_sha256")!=
            witness["raw_source_runtime_receipt_sha256"]):
        result["reason"]="INCOMPLETE_OR_TAMPERED_PRIMARY_EVIDENCE"
        return result
    if claim["claim_type"] not in CLAIMS[:2]:
        result["reason"]="DEPLOYED_IMPACT_OR_GLOBAL_SECURITY_NOT_TESTED"
        return result
    passes=revision=="fixed"
    assertion_passes=claim["claim_type"]=="UPSTREAM_REGRESSION_PASSES"
    result["verdict"]="SUPPORTED" if passes==assertion_passes else "CONTRADICTED"
    result["reason"]="REAL_PARENT_FAILS_FIXED_PASSES_TEST_WITNESS"
    result["source_revision"]=revision
    result["actual_observed_new_upstream_regression"]="PASSES" if passes else "FAILS"
    result["upstream_source_url"]=(
        f"https://github.com/{witness['repository']}/commit/{commit}"
    )
    return result


def stress_cases(index:dict)->list[dict]:
    """Construct 32 self-consistency fixtures; NOT a test of learned accuracy."""
    suite=[]
    for case_id in EXPECTED_IDS:
        witness=index[case_id]
        for revision,correct,incorrect in (
            ("parent","UPSTREAM_REGRESSION_FAILS","UPSTREAM_REGRESSION_PASSES"),
            ("fixed","UPSTREAM_REGRESSION_PASSES","UPSTREAM_REGRESSION_FAILS"),
        ):
            for kind,claim,expected in (
                ("source_supported",correct,"SUPPORTED"),
                ("source_contradicted",incorrect,"CONTRADICTED"),
                ("unsupported_deployment","CONFIRMED_PRODUCTION_EXPLOIT","ABSTAIN"),
                ("unsupported_universal_safety","GUARANTEED_UNIVERSAL_APPLICATION_SAFETY","ABSTAIN"),
            ):
                item={
                    "test_id":case_id+":"+revision+":"+kind,
                    "claim":canonical_claim(witness,revision,claim),
                    "expected":expected,
                }
                suite.append(item)
    require(len(suite)==32 and len({x["test_id"] for x in suite})==32,
            "32 narrow source-test negative controls missing")
    return suite


def run(index_raw:bytes,lock_raw:bytes,*,examples:list|None=None)->dict:
    index=validated_index(index_raw,lock_raw)
    # Only the internal source-derived suite can create "constructed" receipts.
    # A caller's expected field is merely an unverified assertion, even when
    # the asserted result happens to agree with a deterministic source witness.
    internally_constructed = examples is None
    requests=stress_cases(index) if internally_constructed else examples
    require(isinstance(requests,list) and 1<=len(requests)<=MAX_REQUESTS,
            "source review requests missing or oversized")
    ids=set()
    outcomes=[]
    for item in requests:
        require(isinstance(item,dict) and set(item) in (
            {"test_id","claim"},{"test_id","claim","expected"}
        ), "source review input schema invalid")
        ident=item["test_id"]
        require(isinstance(ident,str) and 1<=len(ident)<=160
                and ident not in ids,"source review ID missing or repeated")
        ids.add(ident)
        verdict=evaluate(index,item["claim"])
        row={"test_id":ident,"judgement":verdict}
        if "expected" in item:
            require(item["expected"] in RESULTS, "invalid source fixture expected class")
            if internally_constructed:
                row["constructed_expectation"]=item["expected"]
                row["matches_source_derived_expectation"]=item["expected"]==verdict["verdict"]
            else:
                row["unverified_caller_expected_verdict"]=item["expected"]
                row["matches_unverified_caller_expectation"]=item["expected"]==verdict["verdict"]
        outcomes.append(row)
    checked=internally_constructed and all(
        "matches_source_derived_expectation" in x for x in outcomes
    )
    if checked:
        require(all(x["matches_source_derived_expectation"] for x in outcomes),
                "source-grounded constructed control violated")
    return {
        "schema_version":1,
        "status":STATUS,
        "source_lock_sha256":sha(lock_raw),
        "permanent_witness_index_sha256":sha(index_raw),
        "four_verified_upstream_regression_stages":len(index),
        "distinct_repositories":len({x["repository"] for x in index.values()}),
        "claims_evaluated":len(outcomes),
        "supported":sum(x["judgement"]["verdict"]=="SUPPORTED" for x in outcomes),
        "contradicted":sum(x["judgement"]["verdict"]=="CONTRADICTED" for x in outcomes),
        "abstained":sum(x["judgement"]["verdict"]=="ABSTAIN" for x in outcomes),
        "constructed_fixtures_checked":len(outcomes) if checked else 0,
        "constructed_fixture_matches":sum(
            x.get("matches_source_derived_expectation") is True for x in outcomes
        ) if internally_constructed else 0,
        "expectation_provenance":(
            "INTERNAL_SOURCE_DERIVED_REGRESSION_FIXTURES" if internally_constructed
            else "EXTERNAL_INPUT_UNVERIFIED_CALLER_EXPECTATIONS"
        ),
        "external_caller_expectations_seen":(
            0 if internally_constructed else
            sum("unverified_caller_expected_verdict" in x for x in outcomes)
        ),
        "caller_expectations_not_gold_or_model_accuracy":True,
        "not_a_semantic_or_neural_security_evaluator":True,
        "not_a_telegraph_network_adapter":True,
        "not_an_independent_human_gold_benchmark":True,
        "not_a_blind_model_holdout":True,
        "trained_model_improvement_proven":False,
        "new_anjo_network_evaluation_rows":0,
        "independent_appsec_expert_labels":0,
        "official_hackathon_submission_confirmed":False,
        "scope_warning":(
            "This deterministic typed review claim gate tests whether an asserted "
            "historical upstream regression PASS/FAIL agrees with a pinned public "
            "GitHub Actions execution witness, or is contradicted, or requires "
            "abstention for untested deployed consequences. An automatically "
            "constructed fixture suite is correct by construction; it is NOT "
            "an independent model accuracy score, natural-language judge, "
            "expert gold label, trained adapter or real-world exploit test."
        ),
        "cases":outcomes,
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Check typed source-test claims against four genuine historical upstream executions")
    parser.add_argument("--index",type=Path,required=True)
    parser.add_argument("--source-lock",type=Path,required=True)
    parser.add_argument("--requests",type=Path,
                        help="A JSON array of typed review claims; omit for 32 deterministic construction controls")
    parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink() and
                args.out.resolve()!=args.index.resolve() and
                args.out.resolve()!=args.source_lock.resolve(),
                "output must be write-once, not an input")
        examples=None if args.requests is None else json.loads(read(args.requests,200_000))
        report=run(read(args.index),read(args.source_lock),examples=examples)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(args.out,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(report,f,indent=2,sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status":report["status"],
            "supported":report["supported"],
            "contradicted":report["contradicted"],
            "abstained":report["abstained"],
            "constructed_fixture_matches":report["constructed_fixture_matches"],
            "not_learned_model_accuracy":True,
            "expert_gold":0,
            "saved":str(args.out),
        },indent=2))
        return 0
    except (ValueError,OSError,TypeError,KeyError,IndexError,UnicodeError) as exc:
        parser.exit(1,"FALSUM SOURCE REGRESSION CLAIM VERIFICATION BLOCKED: "+str(exc)[:185]+"\n")


if __name__=="__main__":
    raise SystemExit(main())
