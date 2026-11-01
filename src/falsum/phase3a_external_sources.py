"""Phase 3A: independently sourced application code, verified but NEVER executed.

Read three *outside* public repositories at immutable commits, verify exact Git
blob IDs, and parse their aiohttp static-route call syntax. Not a vulnerability
scanner, runtime test, expert annotation, third-party code execution, or accepted
Telegraph evaluator. The source files are not copied into reports or artifacts.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .phase2w_proof_gate import ProofError, _canonical

STATUS = "PHASE3A_EXTERNAL_GIT_SOURCE_AST_FACTS_NOT_SECURITY_VERDICTS"
CATALOG_STATUS = "EXTERNAL_PUBLIC_APPLICATION_SOURCE_PINNED_NOT_EXECUTED"
MAX_SOURCE_BYTES = 96_000
# A separate code-level allowlist prevents edits to the public research
# JSON from turning this into a generic remote code fetcher.
SOURCE_PINS = (
    ("perspective-external", "perspective-dev/perspective",
     "444865accd46bcfdeb552960ce4f63fe8286de42",
     "examples/python-aiohttp/server.py",
     "6025af225ed0c9c6cfdf0c81abc7a05c8dc9b34b",
     ("EXPLICIT_TRUE", "OMITTED_OPTION"), (47, 48)),
    ("nlweb-external", "nlweb-ai/NLWeb",
     "b423f15d9aeaa023ce75993ac9deed2354597043",
     "AskAgent/python/webserver/routes/static.py",
     "455e333e12de498bf45bec4b8b53541b22431233",
     ("EXPLICIT_FALSE", "EXPLICIT_FALSE"), (45, 56)),
    ("maubot-external", "maubot/maubot",
     "f20825b5e3031a89eb5b2edea7f6f7726ada9a10",
     "maubot/server.py",
     "4ba07eacddda99e4f17b1649f6e9863399e458a8",
     ("OMITTED_OPTION",), (112,)),
)
HASH40 = re.compile(r"[0-9a-f]{40}\Z")


def git_blob(data:bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def validate_contract(contract:dict) -> list[dict]:
    if (not isinstance(contract,dict)
        or set(contract)!={"schema_version","status","intent","research_only",
            "external_app_execution_authorized","advisory","source_projects",
            "trust_boundary"}
        or type(contract["schema_version"]) is not int or contract["schema_version"]!=1
        or contract["status"]!=CATALOG_STATUS
        or contract["intent"]!="SECURITY_REVIEW_GENERAL"
        or contract["research_only"] is not True
        or contract["external_app_execution_authorized"] is not False
        or contract["advisory"]!="GHSA-5h86-8mv2-jq9f"):
        raise ProofError("external source contract lost immutable research-only scope")
    trust=contract["trust_boundary"]
    if not isinstance(trust,dict) or set(trust)!={
        "scope","affected_dependency_version_proven","runtime_import_binding_proven",
        "production_reachability_proven","complete_application_audited",
        "independent_human_labels","real_security_exploits_proven",
        "accepted_anjoman_rows","network_eligible","note"}:
        raise ProofError("incomplete source-only trust boundary")
    for flag in ("affected_dependency_version_proven","runtime_import_binding_proven",
                 "production_reachability_proven","complete_application_audited",
                 "network_eligible"):
        if trust[flag] is not False:
            raise ProofError("external source metadata falsely asserts runtime/eligibility")
    for count in ("independent_human_labels","real_security_exploits_proven",
                  "accepted_anjoman_rows"):
        if type(trust[count]) is not int or trust[count]!=0:
            raise ProofError("source inspection was promoted to independently verified security result")
    rows=contract["source_projects"]
    if not isinstance(rows,list) or len(rows)!=len(SOURCE_PINS):
        raise ProofError("three genuine external project pins required")
    keys=("id","repository","commit","path","git_blob_sha1",
          "expected_values","expected_call_lines")
    for row,pin in zip(rows,SOURCE_PINS):
        if (not isinstance(row,dict) or set(row)!=set(keys)
            or tuple(row.get(k) if k not in ("expected_values","expected_call_lines")
                     else tuple(row[k]) if isinstance(row[k],list) else None
                     for k in keys)!=pin):
            raise ProofError("external source commit, Git blob or observed calls changed")
    return rows


def raw_url(row:dict)->str:
    return (f"https://raw.githubusercontent.com/{row['repository']}/"
            f"{row['commit']}/{row['path']}")


def fetch_verified(row:dict, fetcher=None)->bytes:
    url=raw_url(row)
    parts=urlsplit(url)
    if (parts.scheme!="https" or parts.netloc!="raw.githubusercontent.com"
        or not HASH40.fullmatch(row["commit"])):
        raise ProofError("unapproved or non-immutable external source URL")
    if fetcher is None:
        def fetcher(address:str)->bytes:
            req=Request(address,headers={"User-Agent":"FALSUM-SourceOnly-PinnedResearch/1.0"})
            with urlopen(req,timeout=12) as resp:
                if resp.geturl()!=address or resp.status!=200:
                    raise ProofError("unexpected external host redirect or response")
                data=resp.read(MAX_SOURCE_BYTES+1)
            return data
    blob=fetcher(url)
    if not isinstance(blob,bytes) or len(blob)>MAX_SOURCE_BYTES or not blob:
        raise ProofError("external file is not bounded nonempty bytes")
    if git_blob(blob)!=row["git_blob_sha1"]:
        raise ProofError("upstream file contents did not match exact pinned Git blob")
    try:
        blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProofError("external source is not valid UTF-8 Python") from exc
    return blob


def _is_aiohttp_router_call(call:ast.Call)->bool:
    func=call.func
    return (isinstance(func,ast.Attribute) and func.attr=="add_static"
        and isinstance(func.value,ast.Attribute) and func.value.attr=="router")


def inspect_python(row:dict,data:bytes)->dict:
    try:
        tree=ast.parse(data.decode("utf-8"),filename=row["path"])
    except SyntaxError as exc:
        raise ProofError("verified external Python cannot be parsed") from exc
    imports=[]
    for n in ast.walk(tree):
        if isinstance(n,ast.ImportFrom) and n.module=="aiohttp":
            imports.extend(x.name for x in n.names if x.name=="web")
        elif isinstance(n,ast.Import):
            imports.extend(x.name for x in n.names if x.name=="aiohttp")
    if not imports:
        raise ProofError("external file does not declare aiohttp import in source")
    found=[]
    for node in ast.walk(tree):
        if not isinstance(node,ast.Call) or not _is_aiohttp_router_call(node):
            continue
        if any(k.arg is None for k in node.keywords):
            category="KEYWORD_EXPANSION_UNRESOLVED"
        else:
            flags=[k.value for k in node.keywords if k.arg=="follow_symlinks"]
            if not flags:
                category="OMITTED_OPTION"
            elif len(flags)!=1:
                category="AMBIGUOUS_ARGUMENT"
            elif isinstance(flags[0],ast.Constant) and type(flags[0].value) is bool:
                category="EXPLICIT_TRUE" if flags[0].value else "EXPLICIT_FALSE"
            else:
                category="DYNAMIC_OR_NONBOOLEAN_UNRESOLVED"
        if node.end_lineno is None or node.end_lineno<node.lineno:
            raise ProofError("no bounded source call location")
        found.append({
            "line_start":node.lineno,"line_end":node.end_lineno,
            "observed_keyword_syntax":category,
            "call_ast_sha256":hashlib.sha256(
                ast.dump(node,include_attributes=False).encode()).hexdigest(),
            "receiver_identity_verified":False,
            "framework_version_verified":False,
            "call_executed":False,
            "applicability_conclusion":"UNRESOLVED_NO_DEPLOYMENT_OR_VERSION_PROOF"
        })
    found.sort(key=lambda x:(x["line_start"],x["line_end"]))
    if ([x["observed_keyword_syntax"] for x in found]!=row["expected_values"]
        or [x["line_start"] for x in found]!=row["expected_call_lines"]):
        raise ProofError("external static-call facts differ from pinned, inspected source")
    return {
        "id":row["id"],"repository":row["repository"],"commit":row["commit"],
        "path":row["path"],"source_git_blob_sha1":git_blob(data),
        "full_file_sha256":hashlib.sha256(data).hexdigest(),
        "file_bytes":len(data),"aiohttp_import_declaration_present":True,
        "source_code_executed":False,"static_router_calls":found,
        "external_runtime_tested":False,"dependency_version_proven":False,
        "independently_expert_adjudicated":False
    }


def audit(contract:dict,fetcher=None)->dict:
    rows=validate_contract(contract)
    findings=[inspect_python(row,fetch_verified(row,fetcher=fetcher)) for row in rows]
    observed=Counter(call["observed_keyword_syntax"]
        for project in findings for call in project["static_router_calls"])
    counts=dict(sorted(observed.items()))
    if counts!={"EXPLICIT_FALSE":2,"EXPLICIT_TRUE":1,"OMITTED_OPTION":2}:
        raise ProofError("expected independent projects' exact syntactic cases absent")
    return {
        "schema_version":1,"status":STATUS,"research_only":True,
        "advisory":"GHSA-5h86-8mv2-jq9f",
        "independent_external_project_count":len(findings),
        "source_call_count":sum(map(len,(p["static_router_calls"] for p in findings))),
        "observed_syntactic_states":counts,
        "external_source_commits_and_blobs_verified":True,
        "source_executes_imports_or_applications":False,
        "affected_dependency_versions_proven":False,
        "runtime_exploitability_proven":False,
        "third_party_applications_executed":0,
        "previous_controlled_framework_runtime_is_not_external_runtime":True,
        "independent_expert_ground_truth_labels":0,
        "confirmed_vulnerabilities":0,"network_eligible":False,
        "registered_evaluator":False,"accepted_anjoman_evaluation_rows":0,
        "cases":findings,
        "source_contract_sha256":hashlib.sha256(_canonical(contract)).hexdigest(),
        "boundary":"Three distinct public projects are true external source cases. Their raw source is only read and parsed, NEVER executed. Version/routing/exposure are NOT established, so no True/False/omitted setting becomes a security verdict. Omitted MUST remain unresolved."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Read+verify+AST-analyze immutable external Python applications WITHOUT executing them")
    p.add_argument("--contract",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    a=p.parse_args(argv)
    try:
        if a.out.exists() or a.out.resolve()==a.contract.resolve():
            raise ProofError("refuse overwriting existing research evidence or contract")
        contract=json.loads(a.contract.read_text(encoding="utf-8"))
        report=audit(contract)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(report))
        print(json.dumps({"status":report["status"],"external_projects_verified":3,
                          "static_call_sites":5,"source_states":report["observed_syntactic_states"],
                          "external_app_executions":0,"network_eligible":False},indent=2))
        return 0
    except (ProofError,OSError,TypeError,ValueError,KeyError) as exc:
        p.exit(1,f"FALSUM PHASE3A EXTERNAL APPLICATION RESEARCH ERROR: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
