"""Hash-verified *declared* aiohttp dependency constraints on independent projects.

Never install dependencies, execute upstream setup.py, or infer running
versions from declarations. Different NLWeb requirement profiles are kept
distinct. Git SHA-1 checks complete manifest bytes before parsing text/TOML.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path

from .phase2w_proof_gate import ProofError, _canonical
from .phase3a_external_sources import fetch_verified

STATUS="PHASE3A_EXTERNAL_DEPENDENCY_DECLARATIONS_NOT_RUNTIME_VERSIONS"
CATALOG_STATUS="EXTERNAL_AIOHTTP_DECLARED_DEPENDENCIES_ONLY_NO_INSTALL_PROOF"
PINS=(
 ("perspective-optional-aiohttp","perspective-dev/perspective",
  "444865accd46bcfdeb552960ce4f63fe8286de42",
  "rust/perspective-python/pyproject.toml",
  "a3a296cc6bb807c6b074ce457c97bdb698cb8ed3",
  "toml-optional-aiohttp",77,"aiohttp>=2,<4","perspective_python_optional"),
 ("nlweb-main-askagent-aiohttp","nlweb-ai/NLWeb",
  "b423f15d9aeaa023ce75993ac9deed2354597043",
  "AskAgent/python/requirements.txt",
  "a4c9f65fdad14cc1eea664204527e614f110882a",
  "requirements-text",12,"aiohttp>=3.13.5","nlweb_askagent_python"),
 ("nlweb-azure-aiohttp","nlweb-ai/NLWeb",
  "b423f15d9aeaa023ce75993ac9deed2354597043",
  "requirements_azure.txt",
  "fd9fbf6c7fcb8c1ff80bd2b490fe1a3ce1cd4fd2",
  "requirements-text",5,"aiohttp==3.13.3","nlweb_azure_variant"),
 ("maubot-base-aiohttp","maubot/maubot",
  "f20825b5e3031a89eb5b2edea7f6f7726ada9a10",
  "requirements.txt",
  "35beea99f743af408dd3b1d126dd924e9546fbdb",
  "requirements-text",2,"aiohttp>=3,<4","maubot_base_requirements"),
)
FIELDS=("id","repository","commit","path","git_blob_sha1",
        "manifest_kind","line","declared_requirement","profile")
REQUIREMENT=re.compile(r"^aiohttp(>=|==)([0-9]+(?:\.[0-9]+){0,2})(?:,<([0-9]+(?:\.[0-9]+){0,2}))?$")


def validate(contract:dict)->list[dict]:
    if (not isinstance(contract,dict)
        or set(contract)!={"schema_version","status","research_only","upstream_advisory",
                            "patched_version","external_application_code_executed",
                            "profiles","trust_boundary"}
        or type(contract["schema_version"]) is not int or contract["schema_version"]!=1
        or contract["status"]!=CATALOG_STATUS
        or contract["research_only"] is not True
        or contract["upstream_advisory"]!="GHSA-5h86-8mv2-jq9f"
        or contract["patched_version"]!="3.9.2"
        or contract["external_application_code_executed"] is not False):
        raise ProofError("external declaration contract altered or promoted")
    trust=contract["trust_boundary"]
    if (not isinstance(trust,dict) or set(trust)!={
        "profiles_are_not_single_deployment_environment","installed_versions_verified",
        "dependency_solver_executed","code_imported","security_labels_approved",
        "vulnerabilities_confirmed","accepted_anjoman_evaluation_rows",
        "network_eligible"}):
        raise ProofError("missing declaration-versus-install boundary")
    if trust["profiles_are_not_single_deployment_environment"] is not True:
        raise ProofError("separate NLWeb install profiles were merged")
    for item in ("installed_versions_verified","dependency_solver_executed","code_imported","network_eligible"):
        if trust[item] is not False:
            raise ProofError("dependency declaration was promoted to a runtime fact")
    for item in ("security_labels_approved","vulnerabilities_confirmed","accepted_anjoman_evaluation_rows"):
        if type(trust[item]) is not int or trust[item]!=0:
            raise ProofError("fake independent label or network record")
    rows=contract["profiles"]
    if not isinstance(rows,list) or len(rows)!=len(PINS):
        raise ProofError("four pinned manifest profiles required")
    for row,pinned in zip(rows,PINS):
        if (not isinstance(row,dict) or set(row)!=set(FIELDS)
            or tuple(row.get(k) for k in FIELDS)!=pinned):
            raise ProofError("external manifest, line, profile or expected dependency changed")
    return rows


def _ver(s:str)->tuple[int,int,int]:
    bits=s.split(".")
    if not 1<=len(bits)<=3 or any(not b.isascii() or not b.isdigit() for b in bits):
        raise ProofError("unsupported nonnumeric requirement version")
    return tuple(int(x) for x in (bits+["0"]*(3-len(bits))))


def _constraint_semantics(s:str,patched:str)->str:
    m=REQUIREMENT.fullmatch(s)
    if m is None:
        raise ProofError("unhandled external aiohttp constraint; abstain")
    op,lower,upper=m.groups()
    fix=_ver(patched)
    low=_ver(lower)
    if op=="==":
        if upper is not None:
            raise ProofError("unsupported exact upper bounds")
        return "DECLARATION_REQUIRES_AT_LEAST_FIXED" if low>=fix else "DECLARATION_PINS_AFFECTED_VERSION"
    # We have a required numerical lower bound and optional exclusive upper.
    # If a fixed release is at/below that lower bound, all allowed versions
    # are on the fixed side of this particular historical advisory.
    if upper is not None and _ver(upper)<=low:
        raise ProofError("contradictory version range")
    if low>=fix:
        return "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE"
    # This is only a *possible* older release based on the lower bound.
    # For our exact pinned profiles, the upper bounds do not exclude 3.9.1.
    historical=(3,9,1)
    if low<=historical and (upper is None or historical<_ver(upper)):
        return "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE"
    return "UNRESOLVED_COMPLEX_DECLARED_RANGE"


def read_profile(row:dict,fetcher=None)->dict:
    data=fetch_verified(row,fetcher)
    text=data.decode("utf-8")
    lines=text.splitlines()
    if row["line"]>len(lines) or row["line"]<1:
        raise ProofError("expected real dependency manifest line disappeared")
    if row["manifest_kind"]=="toml-optional-aiohttp":
        try:
            parsed=tomllib.loads(text)
        except tomllib.TOMLDecodeError as e:
            raise ProofError("manifest could not be parsed as TOML") from e
        values=parsed.get("project",{}).get("optional-dependencies",{}).get("aiohttp")
        if not isinstance(values,list) or len(values)!=1 or type(values[0]) is not str:
            raise ProofError("pinned Perspective optional aiohttp dependency missing")
        actual=values[0]
        if actual not in lines[row["line"]-1]:
            raise ProofError("expected TOML dependency line changed")
    elif row["manifest_kind"]=="requirements-text":
        actual=lines[row["line"]-1].strip()
        # Exactly one root aiohttp requirement line, not the aiohttp-cors
        # dependency or an opaque nested include.
        aio_lines=[s.strip() for s in lines if re.match(r"^aiohttp(?=[=<>])",s.strip())]
        if len(aio_lines)!=1:
            raise ProofError("ambiguous independent manifest dependencies")
    else:
        raise ProofError("unsupported dependency profile format")
    if actual!=row["declared_requirement"]:
        raise ProofError("verified upstream source does not declare the expected version range")
    classification=_constraint_semantics(actual,"3.9.2")
    return {
        "id":row["id"],"repository":row["repository"],"commit":row["commit"],
        "manifest_path":row["path"],"manifest_git_blob_sha1":row["git_blob_sha1"],
        "manifest_sha256":hashlib.sha256(data).hexdigest(),
        "profile":row["profile"],"manifest_line":row["line"],
        "declared_requirement":actual,"declared_historic_advisory_range":classification,
        "is_installed_runtime_version":False,
        "is_deployed_application_version":False,
        "dependency_environment_resolved":False,
        "confirmed_vulnerability":False,
        "independent_expert_label":False
    }


def audit(contract:dict,fetcher=None)->dict:
    rows=validate(contract)
    entries=[read_profile(x,fetcher) for x in rows]
    count_possible=sum(x["declared_historic_advisory_range"]==
                       "DECLARATION_PERMITS_HISTORIC_AFFECTED_RANGE" for x in entries)
    count_excluded=sum(x["declared_historic_advisory_range"] in (
                       "DECLARATION_EXCLUDES_HISTORIC_AFFECTED_RANGE",
                       "DECLARATION_REQUIRES_AT_LEAST_FIXED") for x in entries)
    if (count_possible,count_excluded)!=(2,2):
        raise ProofError("version support counts changed in exact external manifests")
    return {
        "schema_version":1,"status":STATUS,"research_only":True,
        "upstream_advisory":contract["upstream_advisory"],
        "fixed_release":contract["patched_version"],
        "pinned_external_manifest_profiles":len(entries),
        "external_projects_with_at_least_one_manifest":3,
        "declaration_profiles_permitting_historical_affected_versions":count_possible,
        "declaration_profiles_excluding_historical_affected_versions":count_excluded,
        "distinct_nlweb_profiles_not_a_single_install":True,
        "manifests_fetched_verified_without_installation":True,
        "third_party_application_executions":0,
        "actual_installed_or_deployed_versions_verified":0,
        "confirmed_application_vulnerabilities":0,
        "human_reviewed_labels":0,
        "accepted_anjoman_rows":0,"network_eligible":False,
        "registered_evaluator":False,
        "profiles":entries,
        "input_catalog_sha256":hashlib.sha256(_canonical(contract)).hexdigest(),
        "interpretation":"These are independent public project dependency DECLARATIONS, not resolved, deployed versions. A permissive requirement is not proof of vulnerable installation. NLWeb AskAgent and Azure are separate profiles with different requirements. No application-execution or exploit result."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Read pinned upstream Python dependency manifests; never execute setup.py or install their code")
    p.add_argument("--contract",required=True,type=Path)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args(argv)
    try:
        if args.out.exists() or args.out.resolve()==args.contract.resolve():
            raise ProofError("refuse overwriting upstream manifest evidence")
        c=json.loads(args.contract.read_text(encoding="utf-8"))
        out=audit(c)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_bytes(_canonical(out))
        print(json.dumps({"status":STATUS,
                          "independent_manifest_profiles":len(out["profiles"]),
                          "permit_historically_affected":out["declaration_profiles_permitting_historical_affected_versions"],
                          "exclude_historically_affected":out["declaration_profiles_excluding_historical_affected_versions"],
                          "installed_versions_verified":0,"network_eligible":False},indent=2))
        return 0
    except (ProofError,OSError,TypeError,KeyError,ValueError) as e:
        p.exit(1,f"FALSUM THIRD PARTY DEPENDENCY SOURCE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
