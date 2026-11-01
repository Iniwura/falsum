"""Reconcile unreviewed claims against independently parsed *local syntax*.

The AST observations are re-computed from the application checkout and must
match the submitted machine packet byte-for-byte (canonical JSON), preventing
forged "machine verified" metadata. A contradictory literal call kwarg is an
actionable RESEARCH REVIEW FLAG, never an exploit verdict or proof of security.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import (
    ProofError, _canonical, evaluate_batch, validate_catalog,
)
from .phase2x_ast_observer import STATUS as AST_STATUS, METHODS, observe

STATUS="PHASE2X_AST_CROSSCHECKED_ASSERTIONS_NOT_INDEPENDENT_APPSEC_LABELS"


def reconcile(catalog: dict, sources: list[dict], batch: dict,
              root: Path, ast_packets: list[dict]) -> dict:
    rules=validate_catalog(catalog,sources)
    if (not isinstance(ast_packets,list) or len(ast_packets)>3
            or any(not isinstance(x,dict) for x in ast_packets)):
        raise ProofError("untrusted AST packet collection")
    original=evaluate_batch(catalog,sources,batch,root)
    verified={}
    for packet in ast_packets:
        if (packet.get("status")!=AST_STATUS
                or packet.get("case_id") not in METHODS
                or packet.get("case_id") in verified
                or packet.get("network_eligible") is not False
                or packet.get("human_reviewed") is not False
                or packet.get("automatically_verified_exploit_preconditions")!=0):
            raise ProofError("forged AST packet source, label or duplicate identity")
        files=packet.get("scanned_files")
        if (not isinstance(files,list) or not files
                or any(not isinstance(f,dict) or set(f)!={"path","sha256","bytes","ast_parse_success"} for f in files)):
            raise ProofError("missing bounded original AST selection")
        same=observe(catalog,sources,packet["case_id"],root,[x["path"] for x in files])
        if _canonical(same)!=_canonical(packet):
            raise ProofError("AST packet did not reproduce from current exact application source")
        verified[packet["case_id"]]=same

    reconciled=[]
    disagreements=0
    corroborations=0
    for case in original["results"]:
        ast=verified.get(case["case_id"])
        observations=ast["observations"] if ast else []
        rows=[]
        for condition in case["preconditions"]:
            for cite in condition["citations"]:
                scoped=[x for x in observations
                        if x["requirement_id"]==condition["requirement_id"]
                        and x["path"]==cite["path"] and x["sha256"]==cite["sha256"]
                        and x["line_start"]<=cite["line_end"]
                        and x["line_end"]>=cite["line_start"]]
                for finding in scoped:
                    implication=finding["syntactic_implication"]
                    claim=cite["claimed_state"]
                    if implication not in ("SYNTACTIC_PRESENT","SYNTACTIC_ABSENT"):
                        consistency="AST_DYNAMIC_OR_UNRESOLVED"
                    elif (claim=="present")==(implication=="SYNTACTIC_PRESENT"):
                        consistency="AST_SYNTAX_CONSISTENT_WITH_SUBMITTER_CLAIM"
                        corroborations+=1
                    else:
                        consistency="AST_SYNTAX_DISAGREES_WITH_SUBMITTER_CLAIM"
                        disagreements+=1
                    rows.append({
                        "requirement_id":condition["requirement_id"],
                        "application_path":finding["path"],"application_sha256":finding["sha256"],
                        "evidence_line_start":cite["line_start"],"evidence_line_end":cite["line_end"],
                        "ast_call_line_start":finding["line_start"],
                        "ast_call_line_end":finding["line_end"],
                        "ast_call_sha256":finding["call_ast_sha256"],
                        "observed_syntax":finding["observation"],
                        "syntactic_implication":implication,
                        "submitted_assertion":claim,
                        "consistency":consistency,
                        "independent_runtime_semantics_verified":False
                    })
        flag=any(r["consistency"]=="AST_SYNTAX_DISAGREES_WITH_SUBMITTER_CLAIM" for r in rows)
        reconciled.append({
            "case_id":case["case_id"],"original_unreviewed_result":case["result"],
            "ast_source_selection_provided":ast is not None,
            "matched_ast_call_citations":len(rows),
            "machine_syntax_disagrees_with_assertion":flag,
            "reconciled_status":(
                "BLOCKED_AST_SYNTAX_CONFLICT_REQUIRES_HUMAN_REVIEW" if flag
                else "UNREVIEWED_ORIGINAL_RESULT_NOT_PROMOTED"
            ),
            "citation_reconciliation":rows,
            "human_review_required":True,
            "verified_actual_runtime_applicability":False,
            "confirmed_exploits":0,"accepted_evaluation_labels":0
        })
    return {
        "schema_version":1,"status":STATUS,"research_only":True,
        "source_pinned":True,"ast_packets_recomputed_from_live_checkout":len(verified),
        "original_evidence_verified":True,"ast_contradictions_found":disagreements,
        "ast_syntactic_agreements_found":corroborations,
        "actual_app_security_semantics_verified":False,
        "verified_exploits":0,"human_approved_labels":0,
        "network_eligible":False,"registered_evaluator":False,
        "original_evidence_report_sha256":hashlib.sha256(_canonical(original)).hexdigest(),
        "ast_packets_sha256":hashlib.sha256(_canonical(ast_packets)).hexdigest(),
        "cases":reconciled,
        "caution":"Machine AST is an exact syntactic observation of selected local calls, not proof of the callee's identity, control flow, deploy version, exploitability or absence elsewhere. No developer assertion is promoted to human-reviewed ground truth."
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Recompute real Python AST and block localized contradictory developer assertions")
    for name in ("catalog","old-queue","train-queue","fresh-spec","batch","ast-packets","root","out"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ProofError("refuse overwriting existing prior evidence")
        from .real_fix_corpus import load_queue
        original=load_queue(args.old_queue)["cases"]
        train=load_queue(args.train_queue)["cases"]
        fresh=json.loads(args.fresh_spec.read_text(encoding="utf-8"))
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("research_only") is not True
                or fresh.get("network_eligible") is not False):
            raise ProofError("not an authorized research source registry")
        catalog=json.loads(args.catalog.read_text(encoding="utf-8"))
        batch=json.loads(args.batch.read_text(encoding="utf-8"))
        packets=json.loads(args.ast_packets.read_text(encoding="utf-8"))
        report=reconcile(catalog,original+train+fresh["cases"],batch,args.root,packets)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(report))
        print(json.dumps({"status":STATUS,"cases":len(report["cases"]),
                          "actual_ast_assertion_conflicts":report["ast_contradictions_found"],
                          "network_eligible":False,"verified_exploits":0},indent=2))
        return 0
    except (ProofError,ValueError,TypeError,KeyError,OSError) as exc:
        parser.exit(1,f"FALSUM AST CLAIM RECONCILIATION ERROR: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
