"""Phase 2X: bounded Python AST observations, NEVER execution or semantic proof.

Only syntactic properties at exactly scoped call sites are reported. No import
resolution, call graph, control-flow, reachability, dependency-version check,
actual network negotiation, or exploitability assertion is performed. Literal
False on one call does NOT establish no other vulnerable call exists.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import MAX_BYTES, ProofError, _inside, _canonical, validate_catalog

STATUS = "PHASE2X_MACHINE_AST_SYNTAX_ONLY_NOT_EXPLOIT_PROOF"
METHODS = {
    "real-aiohttp-static-traversal": ("follow_symlinks_enabled", "follow_symlinks"),
    "fresh-tornado-cookie-attribute": ("untrusted_noninteger_max_age", "max_age"),
    "fresh-websockets-deflate-limit": ("compression_negotiated", "compression"),
}
MAX_FILES = 12
MAX_OBSERVATIONS = 120


def _callee(call: ast.expr, case_id: str) -> bool:
    """Match qualified text only; do not pretend dynamic binding was resolved."""
    if not isinstance(call, ast.Attribute):
        return False
    if case_id == "real-aiohttp-static-traversal":
        return (call.attr == "add_static" and isinstance(call.value, ast.Attribute)
                and call.value.attr == "router")
    if case_id == "fresh-tornado-cookie-attribute":
        return (call.attr == "set_cookie" and isinstance(call.value, ast.Name)
                and call.value.id == "self")
    if case_id == "fresh-websockets-deflate-limit":
        # Qualified only, still no guarantee the global websockets name refers
        # to the upstream dependency or that this call ever executes.
        chain = []
        cur = call
        while isinstance(cur, ast.Attribute):
            chain.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return False
        chain.append(cur.id)
        name = ".".join(reversed(chain))
        return name in {"websockets.serve", "websockets.asyncio.server.serve",
                        "websockets.sync.server.serve"}
    return False


def _literal(expr: ast.expr) -> tuple[str, object | None]:
    if isinstance(expr, ast.Constant):
        value=expr.value
        if value is None: return "LITERAL_NONE", None
        if type(value) is bool: return "LITERAL_BOOL", value
        if type(value) is int: return "LITERAL_INT", value
        if type(value) is str: return "LITERAL_TEXT", value[:120]
        return "OTHER_LITERAL", None
    if (isinstance(expr, ast.UnaryOp) and type(expr.op) in (ast.UAdd,ast.USub)
            and isinstance(expr.operand, ast.Constant) and type(expr.operand.value) is int):
        return "LITERAL_INT", -expr.operand.value if isinstance(expr.op,ast.USub) else expr.operand.value
    return "DYNAMIC_OR_COMPUTED", None


def _classify(call: ast.Call, case_id: str) -> tuple[str,str]:
    requirement, keyword=METHODS[case_id]
    if any(k.arg is None for k in call.keywords):
        return "KWARG_EXPANSION_UNRESOLVED", "UNDETERMINED"
    matches=[k.value for k in call.keywords if k.arg==keyword]
    if len(matches)!=1:
        return "KEYWORD_NOT_EXPLICIT", "UNDETERMINED"
    kind,value=_literal(matches[0])
    if case_id=="real-aiohttp-static-traversal":
        if kind=="LITERAL_BOOL":
            return "EXPLICIT_TRUE" if value else "EXPLICIT_FALSE", "SYNTACTIC_PRESENT" if value else "SYNTACTIC_ABSENT"
        return "DYNAMIC_OR_NONBOOLEAN_FLAG", "UNDETERMINED"
    if case_id=="fresh-tornado-cookie-attribute":
        if kind=="LITERAL_INT":
            return "EXPLICIT_INT_MAX_AGE", "SYNTACTIC_ABSENT"
        # Noninteger literal is NOT proof that an attacker controls it.
        if kind in ("LITERAL_TEXT","LITERAL_NONE","LITERAL_BOOL","OTHER_LITERAL"):
            return "EXPLICIT_NONINTEGER_LITERAL_NOT_PROVEN_UNTRUSTED", "UNDETERMINED"
        return "DYNAMIC_MAX_AGE_UNRESOLVED", "UNDETERMINED"
    if case_id=="fresh-websockets-deflate-limit":
        if kind=="LITERAL_NONE":
            return "EXPLICIT_COMPRESSION_NONE", "SYNTACTIC_ABSENT"
        if kind=="LITERAL_TEXT" and value=="deflate":
            return "EXPLICIT_DEFLATE_ENABLED_NEGOTIATION_UNPROVEN", "UNDETERMINED"
        if kind=="LITERAL_TEXT":
            return "OTHER_COMPRESSION_LITERAL", "UNDETERMINED"
        return "DYNAMIC_COMPRESSION_UNRESOLVED", "UNDETERMINED"
    raise ProofError("unsupported AST research rule")


def observe(catalog: dict, sources: list[dict], case_id: str, root: Path,
            relative_paths: list[str]) -> dict:
    rules=validate_catalog(catalog,sources)
    if case_id not in METHODS or case_id not in rules:
        raise ProofError("AST checker only supports three narrow approved source families")
    if (not isinstance(relative_paths,list) or not 1<=len(relative_paths)<=MAX_FILES
            or len(set(relative_paths))!=len(relative_paths)):
        raise ProofError("distinct 1..12 explicitly selected local files required")
    observations=[]
    files=[]
    for rel in relative_paths:
        path=_inside(root,rel)
        if path.suffix!=".py" or path.stat().st_size>MAX_BYTES:
            raise ProofError("bounded Python source file only")
        raw=path.read_bytes()
        sha=hashlib.sha256(raw).hexdigest()
        try:
            body=raw.decode("utf-8")
            tree=ast.parse(body,filename=rel)
        except (SyntaxError,UnicodeDecodeError,ValueError) as e:
            raise ProofError("unsupported or malformed Python source; abstain") from e
        lines=body.splitlines()
        files.append({"path":rel,"sha256":sha,"bytes":len(raw),
                      "ast_parse_success":True})
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call) or not _callee(node.func,case_id):
                continue
            if not (isinstance(node.lineno,int) and isinstance(node.end_lineno,int)
                    and node.end_lineno>=node.lineno):
                raise ProofError("unbounded AST call location")
            # The observation cites the full syntactic call, unlike quoting an
            # arbitrary unrelated developer-supplied source line.
            if node.end_lineno-node.lineno>14 or node.end_lineno>len(lines):
                raise ProofError("call spans too many lines; abstain rather than omit")
            kind,implication=_classify(node,case_id)
            quote="\n".join(lines[node.lineno-1:node.end_lineno])
            observations.append({
                "case_id":case_id,
                "requirement_id":METHODS[case_id][0],
                "path":rel,"sha256":sha,
                "line_start":node.lineno,"line_end":node.end_lineno,
                "quote":quote,
                "call_ast_sha256":hashlib.sha256(
                    ast.dump(node,include_attributes=False).encode("utf-8")
                ).hexdigest(),
                "observation":kind,"syntactic_implication":implication,
                "callee_identity_verified":False,
                "call_execution_verified":False,
                "actual_library_version_verified":False,
                "application_wide_absence_proven":False,
            })
            if len(observations)>MAX_OBSERVATIONS:
                raise ProofError("too many matching call sites; abstain")
    return {
        "schema_version":1,"status":STATUS,"intent":"SECURITY_REVIEW_GENERAL",
        "case_id":case_id,"repository":rules[case_id]["repository"],
        "source_commit":rules[case_id]["source_commit"],
        "source_catalog_sha256":hashlib.sha256(_canonical(catalog)).hexdigest(),
        "research_only":True,"human_reviewed":False,"network_eligible":False,
        "machine_verified_python_ast_syntax":True,
        "automatically_verified_exploit_preconditions":0,
        "version_reachability_or_alias_binding_proven":False,
        "scanned_files":files,"observations":observations,
        "scope_notice":"Only Python call-expression syntax in explicitly selected files. No runtime execution, library/callee binding proof, reachability, version or whole-app absence is established."
    }


def main(argv:list[str]|None=None)->int:
    parser=argparse.ArgumentParser(description="Report exact Python AST constant-kwarg facts without pretending to prove vulnerabilities")
    for field in ("catalog","old-queue","train-queue","fresh-spec","root","paths-json","out"):
        parser.add_argument("--"+field,required=True,type=Path)
    parser.add_argument("--case-id",required=True)
    args=parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ProofError("refuse overwriting prior machine evidence")
        from .real_fix_corpus import load_queue
        old=load_queue(args.old_queue)["cases"]
        train=load_queue(args.train_queue)["cases"]
        fresh=json.loads(args.fresh_spec.read_text(encoding="utf-8"))
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False):
            raise ProofError("research-only fresh source origin required")
        paths=json.loads(args.paths_json.read_text(encoding="utf-8"))
        if not isinstance(paths,dict) or set(paths)!={"status","files"} or paths["status"]!="EXPLICIT_AST_FILE_SELECTION_UNREVIEWED":
            raise ProofError("file selection must be explicit and unreviewed")
        catalog=json.loads(args.catalog.read_text(encoding="utf-8"))
        report=observe(catalog,old+train+fresh["cases"],args.case_id,args.root,paths["files"])
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(report))
        print(json.dumps({"status":STATUS,"selected_files":len(report["scanned_files"]),
                          "scoped_call_observations":len(report["observations"]),
                          "actual_exploits_confirmed":0,"network_eligible":False},indent=2))
        return 0
    except (OSError,ValueError,TypeError,KeyError,ProofError) as e:
        parser.exit(1,f"FALSUM AST SCOPE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
