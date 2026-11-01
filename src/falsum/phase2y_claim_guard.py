"""Phase 2Y: cross-check assertions ONLY at statically bound source calls.

Repairs Phase2X's key limitation: fake router.add_static lookalikes must
not receive credible aiohttp-related contradiction flags. Recompute source.
No runtime import identity, call reachability, version or exploit proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import ProofError, _canonical, evaluate_batch, validate_catalog
from .phase2y_bindings import STATUS as BIND_STATUS, analyze

STATUS="PHASE2Y_IMPORT_BOUND_LOCAL_CLAIM_REVIEW_NOT_EXPLOIT_LABEL"
PATHS={"MODULE_TOP_LEVEL_CALL_SYNTAX","DIRECT_MODULE_CALL_TO_LOCAL_FUNCTION_SYNTAX"}
CALLBACK="FRAMEWORK_CALLBACK_EXECUTION_UNVERIFIED"


def guard(catalog:dict,sources:list[dict],batch:dict,root:Path,
          binding_packets:list[dict])->dict:
    rules=validate_catalog(catalog,sources)
    original=evaluate_batch(catalog,sources,batch,root)
    if not isinstance(binding_packets,list) or len(binding_packets)>3:
        raise ProofError("one machine binding packet per scoped framework case only")
    verified={}
    for packet in binding_packets:
        if (not isinstance(packet,dict) or packet.get("status")!=BIND_STATUS
                or packet.get("case_id") not in rules
                or packet.get("case_id") in verified
                or packet.get("network_eligible") is not False
                or packet.get("runtime_imports_loaded") is not False
                or packet.get("runtime_calls_executed") is not False
                or packet.get("verified_exploitability") is not False
                or packet.get("accepted_security_labels")!=0):
            raise ProofError("forged source binding report or duplicate case")
        files=packet.get("scanned_files")
        if (not isinstance(files,list) or not files
                or any(not isinstance(f,dict) or set(f)!={
                    "path","sha256","python_ast_parsed","observed_import_names",
                    "static_aiohttp_constructor_targets","runtime_imports_executed"
                } for f in files)):
            raise ProofError("invalid scoped application file list")
        rerun=analyze(catalog,sources,packet["case_id"],root,[x["path"] for x in files])
        if _canonical(rerun)!=_canonical(packet):
            raise ProofError("claim's machine report did not reproduce against current app source")
        verified[packet["case_id"]]=rerun
    results=[]
    contradictions=0
    unresolved=0
    for case in original["results"]:
        machine=verified.get(case["case_id"])
        eligible=machine["bound_syntactic_calls"] if machine else []
        evidence=[]
        for condition in case["preconditions"]:
            for citation in condition["citations"]:
                matched=[x for x in eligible if
                         x["path"]==citation["path"]
                         and x["sha256"]==citation["sha256"]
                         and x["line_start"]<=citation["line_end"]
                         and x["line_end"]>=citation["line_start"]
                         and condition["requirement_id"] in (
                            "follow_symlinks_enabled","untrusted_noninteger_max_age",
                            "compression_negotiated")]
                for x in matched:
                    implication=x["literal_keyword_implication"]
                    observed=x["syntactic_invocation_path"]
                    claim=citation["claimed_state"]
                    if (observed not in PATHS and observed!=CALLBACK):
                        verdict="UNRESOLVED_STATIC_INVOCATION_PATH"
                    elif implication not in ("SYNTACTIC_PRESENT","SYNTACTIC_ABSENT"):
                        verdict="DYNAMIC_OR_UNDETERMINED_AST_LITERAL"
                    elif (claim=="present")==(implication=="SYNTACTIC_PRESENT"):
                        verdict="LOCAL_STATIC_SYNTAX_AGREES_WITH_ASSERTION"
                    else:
                        verdict="LOCAL_STATIC_SYNTAX_CONTRADICTS_ASSERTION_REVIEW_REQUIRED"
                        contradictions+=1
                    if verdict.startswith("UNRESOLVED") or verdict.startswith("DYNAMIC"):
                        unresolved+=1
                    evidence.append({
                        "requirement_id":condition["requirement_id"],
                        "claim":claim,"syntactic_implication":implication,
                        "binding_declaration":x["import_declaration_binding"],
                        "invocation_path":observed,"review_verdict":verdict,
                        "path":x["path"],"sha256":x["sha256"],
                        "line_start":x["line_start"],"line_end":x["line_end"],
                        "ast_sha256":x["ast_sha256"],
                        "actual_runtime_callee_verified":False,
                    })
        conflict=any(x["review_verdict"]==
                     "LOCAL_STATIC_SYNTAX_CONTRADICTS_ASSERTION_REVIEW_REQUIRED"
                     for x in evidence)
        results.append({
            "case_id":case["case_id"],
            "original_evidence_decision":case["result"],
            "binding_packet_for_case":machine is not None,
            "matched_local_bound_call_observations":len(evidence),
            "requires_review_for_local_syntax_conflict":conflict,
            "decision":"STATIC_SYNTAX_CONTRADICTION_HUMAN_REVIEW_REQUIRED"
                if conflict else "ABSTAIN_NO_BINDING_QUALIFIED_CONTRADICTION",
            "details":evidence,
            "confirmed_vulnerability":False,
            "human_review_required":True
        })
    return {
        "schema_version":1,"status":STATUS,
        "source_catalog_sha256":hashlib.sha256(_canonical(catalog)).hexdigest(),
        "original_phase2w_evidence_sha256":hashlib.sha256(_canonical(original)).hexdigest(),
        "research_only":True,"network_eligible":False,
        "recomputed_binding_reports":len(verified),
        "local_source_syntax_conflicts":contradictions,
        "unresolved_scoped_call_sites":unresolved,
        "actual_framework_runtime_binding_verified":False,
        "actual_exploits_proven":0,"human_approved_labels":0,
        "accepted_anjoman_rows":0,"evaluator_registered":False,
        "cases":results,
        "limitation":"Static import declarations and syntactic call paths are not runtime Python module identity, production execution, deployment version, data flow or exploitability. A missing bound call is NOT proof of safety."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Require local static source import evidence before flagging a developer claim contradiction")
    for k in ("catalog","old-queue","train-queue","fresh-spec","batch","binding-packets","root","out"):
        p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ProofError("refuse to overwrite existing application or review evidence")
        from .real_fix_corpus import load_queue
        orig=load_queue(a.old_queue)["cases"]
        train=load_queue(a.train_queue)["cases"]
        fresh=json.loads(a.fresh_spec.read_text(encoding="utf-8"))
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False):
            raise ProofError("non-research public source pool")
        catalog=json.loads(a.catalog.read_text(encoding="utf-8"))
        batch=json.loads(a.batch.read_text(encoding="utf-8"))
        packets=json.loads(a.binding_packets.read_text(encoding="utf-8"))
        result=guard(catalog,orig+train+fresh["cases"],batch,a.root,packets)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(result))
        print(json.dumps({"status":STATUS,"cases":len(result["cases"]),
                          "local_static_syntax_conflicts":result["local_source_syntax_conflicts"],
                          "confirmed_exploits":0,"network_eligible":False},indent=2))
        return 0
    except (ProofError,ValueError,KeyError,TypeError,OSError) as e:
        p.exit(1,f"FALSUM PHASE2Y CLAIM REVIEW ERROR: {e}\n")

if __name__=="__main__":
    raise SystemExit(main())
