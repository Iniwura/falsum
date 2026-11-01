"""Phase 2Z: controlled *real installed* aiohttp runtime versus pinned static evidence.

Executes ONLY three source-controlled FALSUM illustrative modules under the
exact aiohttp==3.10.11 environment. It uses TestServer on loopback 127.0.0.1
to verify ordinary file responses and inspects the actual registered
StaticResource flag. This is NOT an old-CVE reproduction or proof of safety,
and must never import arbitrary application code supplied by a reviewer.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib
from importlib.metadata import version
import inspect
import json
from pathlib import Path

from .phase2w_proof_gate import ProofError, _canonical
from .phase2y_bindings import analyze

STATUS="PHASE2Z_CONTROLLED_AIOHTTP_RUNTIME_CORRELATION_NOT_VULNERABILITY_ACCURACY"
ALLOWED=(
    ("secure","examples.phase2z_runtime_pilot.secure_static","examples/phase2z_runtime_pilot/secure_static.py",False,"SYNTACTIC_ABSENT"),
    ("permissive","examples.phase2z_runtime_pilot.permissive_static","examples/phase2z_runtime_pilot/permissive_static.py",True,"SYNTACTIC_PRESENT"),
    ("dynamic","examples.phase2z_runtime_pilot.dynamic_static","examples/phase2z_runtime_pilot/dynamic_static.py",False,"UNDETERMINED"),
)
CASE="real-aiohttp-static-traversal"
VERSION="3.10.11"


def validate_contract(spec:dict)->list[dict]:
    if (not isinstance(spec,dict) or
            set(spec)!={"schema_version","status","framework","installed_version","advisory",
                        "patched_since","source_case","only_allowed_python_modules","fixtures",
                        "trusted_input_notice","independent_human_reviews",
                        "live_vulnerabilities_confirmed","network_eligible","limits"}
            or spec.get("schema_version")!=1
            or spec.get("status")!="CONTROLLED_PATCHED_AIOHTTP_RUNTIME_PILOT_RESEARCH_ONLY"
            or spec.get("framework")!="aiohttp"
            or spec.get("installed_version")!=VERSION
            or spec.get("patched_since")!="3.9.2"
            or spec.get("advisory")!="GHSA-5h86-8mv2-jq9f"
            or spec.get("source_case")!=CASE
            or spec.get("independent_human_reviews")!=0
            or spec.get("live_vulnerabilities_confirmed")!=0
            or spec.get("network_eligible") is not False):
        raise ProofError("pilot input identity/eligibility does not match the locked patched framework")
    if (not isinstance(spec["only_allowed_python_modules"],list)
            or spec["only_allowed_python_modules"]!=[row[1] for row in ALLOWED]):
        raise ProofError("attempt to import application module beyond controlled allowlist")
    rows=spec.get("fixtures")
    if not isinstance(rows,list) or len(rows)!=len(ALLOWED):
        raise ProofError("exactly three controlled and explicit source fixtures required")
    for row,expected in zip(rows,ALLOWED):
        if (not isinstance(row,dict)
                or set(row)!={"name","module","path","expected_runtime_flag","expected_syntax"}
                or tuple(row.get(k) for k in (
                    "name","module","path","expected_runtime_flag","expected_syntax"))!=expected
                or type(row.get("expected_runtime_flag")) is not bool):
            raise ProofError("changed source fixture, surplus fields or expected real runtime result")
    return rows


def _original_files(root:Path,rows:list[dict])->list[Path]:
    if not root.exists() or not root.is_dir():
        raise ProofError("pilot repository checkout missing")
    locations=[]
    for row in rows:
        file=(root/row["path"]).resolve(strict=True)
        if file!=root.resolve()/row["path"] or not file.is_file() or file.is_symlink():
            raise ProofError("fixture path escapes tracked repository")
        locations.append(file)
    return locations


def reconcile_observations(report:dict,rows:list[dict])->dict:
    """Cross-check actual runtime flags with independent Phase2Y source evidence."""
    results=report.get("results")
    if not isinstance(results,list) or len(results)!=3:
        raise ProofError("missing three real runtime scenarios")
    for item,expected in zip(results,rows):
        if (item.get("fixture")!=expected["name"]
                or item.get("static_source_keyword")!=expected["expected_syntax"]
                or type(item.get("runtime_registered_follow_symlinks")) is not bool
                or item.get("runtime_registered_follow_symlinks") is not expected["expected_runtime_flag"]
                or item.get("loopback_public_http_status")!=200
                or item.get("loopback_missing_http_status")!=404
                or item.get("runtime_bound_to_installed_aiohttp") is not True
                or item.get("runtime_route_source_and_static_hash_match") is not True):
            raise ProofError("static-to-runtime pilot source or observed behavior does not match")
        if expected["name"]=="dynamic" and item.get("static_source_keyword")!="UNDETERMINED":
            raise ProofError("dynamic config was falsely promoted to known static argument")
        if item.get("actual_exploit_reproduced") is not False:
            raise ProofError("unsupported exploit demonstration or forged status")
    return {
        "scenarios":len(results),
        "runtime_routes_verified":len(results),
        "literal_static_flag_correspondences":2,
        "dynamic_config_static_abstentions":1,
        "actual_exploits_reproduced":0
    }


async def _loopback_tests(app, expected_file:bytes)->tuple[int,int]:
    # TestServer uses a *loopback-only* ephemeral port. It cannot be reached
    # through a public URL and the client never makes outbound HTTP calls.
    from aiohttp.test_utils import TestServer, TestClient
    server=TestServer(app,host="127.0.0.1",port=0)
    async with TestClient(server) as client:
        async with client.get("/assets/public.txt",allow_redirects=False) as resp:
            valid_code=resp.status
            contents=await resp.read()
        async with client.get("/assets/not-a-file.txt",allow_redirects=False) as resp:
            missing_code=resp.status
            await resp.read()
    if valid_code!=200 or contents!=expected_file or missing_code!=404:
        raise ProofError("real installed aiohttp did not serve exact fixture file and reject missing file")
    return valid_code,missing_code


def run_pilot(spec:dict,catalog:dict,sources:list[dict],root:Path)->dict:
    rows=validate_contract(spec)
    files=_original_files(root,rows)
    from aiohttp import web
    from aiohttp.web_urldispatcher import StaticResource
    import aiohttp
    installed=version("aiohttp")
    if aiohttp.__version__!=VERSION or installed!=VERSION:
        raise ProofError("installed aiohttp distribution does not exactly match pinned patched release")
    actual_path=Path(inspect.getfile(StaticResource)).resolve()
    if actual_path.is_relative_to(root.resolve()) or not actual_path.is_file():
        raise ProofError("runtime aiohttp implementation must be installed outside application checkout")
    runtime_sha=hashlib.sha256(actual_path.read_bytes()).hexdigest()
    asset=(root/"examples/phase2z_runtime_pilot/assets/public.txt").resolve(strict=True)
    asset_bytes=asset.read_bytes()
    if not asset_bytes or len(asset_bytes)>2000:
        raise ProofError("missing bounded harmless public asset")
    observed=[]
    for row,source in zip(rows,files):
        stat=analyze(catalog,sources,CASE,root,[row["path"]])
        matches=stat["bound_syntactic_calls"]
        if len(matches)!=1 or matches[0]["path"]!=row["path"] or matches[0]["syntactic_invocation_path"]!="MODULE_TOP_LEVEL_CALL_SYNTAX":
            raise ProofError("correlated source must be a single simple module-level aiohttp call")
        static=matches[0]
        if static["literal_keyword_implication"]!=row["expected_syntax"]:
            raise ProofError("source AST diverges from pre-registered test conditions")
        if static["sha256"]!=hashlib.sha256(source.read_bytes()).hexdigest():
            raise ProofError("application source changed after static inspection")
        # This is an allowlisted source-owned fixture: never use this code path
        # to import user-supplied repository modules or run unknown programs.
        module=importlib.import_module(row["module"])
        if Path(module.__file__).resolve()!=source:
            raise ProofError("unexpected imported fixture module")
        app=module.app
        if type(app) is not web.Application:
            raise ProofError("not exactly the actual installed aiohttp Application class")
        routes=[r for r in app.router.resources() if type(r) is StaticResource]
        if len(routes)!=1:
            raise ProofError("not exactly one installed aiohttp StaticResource")
        route=routes[0]
        flag=getattr(route,"_follow_symlinks",None)
        if type(flag) is not bool:
            raise ProofError("actual installed aiohttp did not expose boolean configured route flag")
        if flag is not row["expected_runtime_flag"]:
            raise ProofError("real app configuration differs from pinned pilot expectation")
        valid_code,missing_code=asyncio.run(_loopback_tests(app,asset_bytes))
        observed.append({
            "fixture":row["name"],"application_source":row["path"],
            "source_sha256":static["sha256"],
            "call_ast_sha256":static["ast_sha256"],
            "static_source_keyword":static["literal_keyword_implication"],
            "statically_import_declared":static["import_declaration_binding"],
            "static_invocation_path":static["syntactic_invocation_path"],
            "runtime_bound_to_installed_aiohttp":True,
            "runtime_installed_aiohttp_version":installed,
            "runtime_resource_class":"aiohttp.web_urldispatcher.StaticResource",
            "runtime_registered_follow_symlinks":flag,
            "runtime_route_source_and_static_hash_match":True,
            "loopback_public_http_status":valid_code,
            "loopback_missing_http_status":missing_code,
            "loopback_only":True,"external_network_requests":0,
            "actual_exploit_reproduced":False,
            "application_security_confirmed":False,
        })
    report={
        "schema_version":1,"status":STATUS,
        "research_only":True,"source_case":CASE,"advisory":spec["advisory"],
        "installed_patched_aiohttp_version":installed,
        "actual_installed_aiohttp_source_file_sha256":runtime_sha,
        "installed_aiohttp_source_module":"aiohttp.web_urldispatcher",
        "research_applications_executed":3,
        "real_customer_apps_tested":0,
        "controlled_loopback_requests":6,
        "results":observed,
        "human_reviews":0,"independent_accuracy_established":False,
        "network_eligible":False,"registered_evaluator":False,
        "confirmed_vulnerabilities":0,
        "research_limit":"This records real behavior in pinned patched aiohttp, under three source-controlled example applications. No historic CVE exploit was reproduced, no arbitrary customer code executed and no general vulnerability accuracy established.",
        "contract_sha256":hashlib.sha256(_canonical(spec)).hexdigest()
    }
    report["reconciliation"]=reconcile_observations(report,rows)
    return report


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Execute three vetted example apps in a genuine patched aiohttp runtime on loopback only")
    for k in ("contract","catalog","old-queue","train-queue","fresh-spec","root","out"):
        p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ProofError("refuse to overwrite earlier runtime evidence")
        from .real_fix_corpus import load_queue
        old=load_queue(a.old_queue)["cases"]
        train=load_queue(a.train_queue)["cases"]
        fresh=json.loads(a.fresh_spec.read_text())
        if (fresh.get("status")!="FRESH_PUBLIC_PROJECT_TRANSFER_DIAGNOSTIC_NO_TRAINING"
                or fresh.get("network_eligible") is not False):
            raise ProofError("historical source inventory is not quarantined")
        spec=json.loads(a.contract.read_text())
        catalog=json.loads(a.catalog.read_text())
        report=run_pilot(spec,catalog,old+train+fresh["cases"],a.root)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(report))
        print(json.dumps({"status":STATUS,"patched_aiohttp_version":VERSION,
                          "controlled_apps_executed":len(report["results"]),
                          "real_loopback_requests":report["controlled_loopback_requests"],
                          "dynamic_syntax_abstentions":report["reconciliation"]["dynamic_config_static_abstentions"],
                          "confirmed_exploits":0,"network_eligible":False},indent=2))
        return 0
    except (ProofError,ValueError,KeyError,TypeError,OSError,ImportError,RuntimeError) as exc:
        p.exit(1,f"FALSUM 2Z PATCHED FRAMEWORK RUNTIME PILOT ERROR: {exc}\n")

if __name__=="__main__":
    raise SystemExit(main())
