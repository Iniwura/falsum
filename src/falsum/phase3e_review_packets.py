"""Phase 3E: reproducible, independent-source security review packets.

Generate FALSUM research material from reverified *third-party* application
and dependency source, never from invented runtime versions or model labels.
The resulting questions and candidate answers are for independent human
review, NOT automatically eligible Anjoman evaluation contributions.

Data crossing this boundary must already have been checked against immutable
Git blob hashes by phase3a_external_sources and phase3a_dependency_manifests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .phase2w_proof_gate import _canonical, ProofError
from .phase3a_external_sources import (
    STATUS as CODE_STATUS, SOURCE_PINS, audit as audit_code,
)
from .phase3a_dependency_manifests import (
    STATUS as DEPS_STATUS, PINS as DEPS_PINS, audit as audit_deps,
)

STATUS="PHASE3E_INDEPENDENT_SOURCE_REVIEW_PACKETS_UNADJUDICATED"
SCHEMA_VERSION=1
MAX_CASES=5


def _sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()


def _review_prompt(syntax:str,profile:str,requirement:str,classification:str)->str:
    if syntax=="EXPLICIT_TRUE":
        observed="The call explicitly passes follow_symlinks=True."
    elif syntax=="EXPLICIT_FALSE":
        observed="The call explicitly passes follow_symlinks=False."
    elif syntax=="OMITTED_OPTION":
        observed="The call omits follow_symlinks; the runtime default has not been verified."
    else:
        raise ProofError("review packet contains unapproved source call state")
    return (
        f"Assess historical CVE-2024-23334 only for this pinned source call. {observed} "
        f"An upstream dependency declaration in profile '{profile}' is '{requirement}' "
        f"({classification}); this is not the resolved version actually installed. "
        "What evidence supports or limits a finding? Distinguish source syntax, "
        "dependency declaration, actual package version, route execution, "
        "untrusted input, attacker-influenced filesystem state and exploit confirmation."
    )


def _answers(syntax:str)->tuple[str,str]:
    # Candidate answers are intentionally debatable and MUST NOT be treated
    # as accepted 'good/bad' labels without a truly independent reviewer.
    if syntax=="EXPLICIT_TRUE":
        return (
            "The explicit True is a source-level prerequisite for this historical issue. "
            "The declared version range may or may not admit affected releases, but no "
            "deployed package version, real route registration, attacker-influenced "
            "symlink path or exploit has been verified. Request those facts.",
            "The explicit True and a dependency range that allows vulnerable releases "
            "establish that this application uses an affected aiohttp release in "
            "production. Flag the issue as an applicable CVE, while keeping "
            "actual exploit reproduction as a separate follow-up.",
        )
    if syntax=="EXPLICIT_FALSE":
        return (
            "This particular source call supplies False, so this observed call "
            "does not show the advisory's symlink-following prerequisite. "
            "Do not infer the whole project is secure or that the route was "
            "executed; review other call sites and the deployed environment.",
            "Because this route explicitly passes False, the entire project's "
            "deployed static-routing surface can be classified as unaffected by "
            "this CVE without checking other call sites, adapters or runtime changes.",
        )
    return (
        "The flag is omitted in this source call. Establish the exact "
        "installed aiohttp version, effective default and actual registered "
        "route before deciding if the advisory prerequisite is present. "
        "An omitted keyword alone is not a proof of security.",
        "An omitted follow_symlinks argument is generally equivalent to "
        "the library's default False configuration. Classify the deployed "
        "route as unaffected without checking the installed implementation "
        "or whether route initialization changes the default.",
    )


def build(source_report:dict,manifest_report:dict)->dict:
    if (not isinstance(source_report,dict) or source_report.get("status")!=CODE_STATUS
        or source_report.get("external_source_commits_and_blobs_verified") is not True
        or source_report.get("source_executes_imports_or_applications") is not False
        or source_report.get("network_eligible") is not False
        or source_report.get("confirmed_vulnerabilities")!=0
        or source_report.get("independent_expert_ground_truth_labels")!=0
        or source_report.get("independent_external_project_count")!=3
        or source_report.get("source_call_count")!=5):
        raise ProofError("outside source data is not exactly verified or still under review")
    if (not isinstance(manifest_report,dict) or manifest_report.get("status")!=DEPS_STATUS
        or manifest_report.get("manifests_fetched_verified_without_installation") is not True
        or manifest_report.get("third_party_application_executions")!=0
        or manifest_report.get("actual_installed_or_deployed_versions_verified")!=0
        or manifest_report.get("human_reviewed_labels")!=0
        or manifest_report.get("network_eligible") is not False
        or manifest_report.get("pinned_external_manifest_profiles")!=4):
        raise ProofError("outside dependency manifest does not preserve uninstalled status")

    source_cases=source_report.get("cases")
    profiles=manifest_report.get("profiles")
    if not isinstance(source_cases,list) or len(source_cases)!=3:
        raise ProofError("exactly three real upstream source files required")
    if not isinstance(profiles,list) or len(profiles)!=4:
        raise ProofError("exactly four different requirement profiles required")

    # Recheck every source identity against CODE-LEVEL pins, not only a JSON
    # field provided by a previous report. It is not a generic prompt factory.
    for source,pin in zip(source_cases,SOURCE_PINS):
        if (source.get("id")!=pin[0]
            or source.get("repository")!=pin[1]
            or source.get("commit")!=pin[2]
            or source.get("path")!=pin[3]
            or source.get("source_git_blob_sha1")!=pin[4]
            or not isinstance(source.get("full_file_sha256"),str)
            or len(source["full_file_sha256"])!=64
            or source.get("source_code_executed") is not False
            or source.get("external_runtime_tested") is not False
            or source.get("dependency_version_proven") is not False):
            raise ProofError("external application identity or trust state modified")
        calls=source.get("static_router_calls")
        if (not isinstance(calls,list)
            or [x.get("observed_keyword_syntax") for x in calls]!=list(pin[5])
            or [x.get("line_start") for x in calls]!=list(pin[6])
            or any(x.get("receiver_identity_verified") is not False
                   or x.get("framework_version_verified") is not False
                   or x.get("call_executed") is not False
                   or x.get("applicability_conclusion")!="UNRESOLVED_NO_DEPLOYMENT_OR_VERSION_PROOF"
                   or not isinstance(x.get("call_ast_sha256"),str)
                   or len(x["call_ast_sha256"])!=64
                   for x in calls)):
            raise ProofError("external AST call observations changed or promoted")

    for profile,pin in zip(profiles,DEPS_PINS):
        if (profile.get("id")!=pin[0]
            or profile.get("repository")!=pin[1]
            or profile.get("commit")!=pin[2]
            or profile.get("manifest_path")!=pin[3]
            or profile.get("manifest_git_blob_sha1")!=pin[4]
            or profile.get("manifest_line")!=pin[6]
            or profile.get("declared_requirement")!=pin[7]
            or profile.get("profile")!=pin[8]
            or profile.get("is_installed_runtime_version") is not False
            or profile.get("is_deployed_application_version") is not False
            or profile.get("dependency_environment_resolved") is not False
            or profile.get("confirmed_vulnerability") is not False
            or profile.get("independent_expert_label") is not False):
            raise ProofError("installed/deployed dependency fact or profile was forged")

    out=[]
    for source in source_cases:
        available=[p for p in profiles if p["repository"]==source["repository"] and p["commit"]==source["commit"]]
        if not available or len(available)>2:
            raise ProofError("upstream dependency profiles do not match source revision")
        # NLWeb's two requirement files are distinct alternatives.
        # Keep the provenance of ALL profiles with every NLWeb callsite.
        for call in source["static_router_calls"]:
            syntax=call["observed_keyword_syntax"]
            answers=_answers(syntax)
            case_id=(source["id"]+"-line-"+str(call["line_start"]))
            requirement_text=" / ".join(p["declared_requirement"] for p in available)
            profiles_text=", ".join(p["profile"] for p in available)
            range_text=" / ".join(p["declared_historic_advisory_range"] for p in available)
            question=_review_prompt(syntax,profiles_text,requirement_text,range_text)
            out.append({
                "packet_id":case_id,
                "advisory":"GHSA-5h86-8mv2-jq9f",
                "source":{
                    "repository":source["repository"],"commit":source["commit"],
                    "path":source["path"],"git_blob_sha1":source["source_git_blob_sha1"],
                    "whole_file_sha256":source["full_file_sha256"],
                    "call_ast_sha256":call["call_ast_sha256"],
                    "line_start":call["line_start"],"line_end":call["line_end"],
                    "observed_call_syntax":syntax,
                    "view_url":(
                        f"https://github.com/{source['repository']}/blob/{source['commit']}/"
                        f"{source['path']}#L{call['line_start']}-L{call['line_end']}"
                    ),
                },
                "dependency_declarations":[{
                    "profile":p["profile"],"path":p["manifest_path"],
                    "git_blob_sha1":p["manifest_git_blob_sha1"],
                    "declared_requirement":p["declared_requirement"],
                    "declared_historic_range":p["declared_historic_advisory_range"],
                    "manifest_line":p["manifest_line"],
                    "view_url":(
                        f"https://github.com/{p['repository']}/blob/{p['commit']}/"
                        f"{p['manifest_path']}#L{p['manifest_line']}"
                    ),
                    "confirmed_actual_install":False
                } for p in available],
                "review_question":question,
                "candidate_answers":[
                    {"id":"A","text":answers[0]},
                    {"id":"B","text":answers[1]},
                ],
                "candidate_answer_sha256":[_sha(a.encode()) for a in answers],
                "label_status":"NOT_INDEPENDENTLY_ADJUDICATED",
                "reviewer_preference":None,
                "reviewer_identity_verified":False,
                "verified_deployed_version":None,
                "verified_runtime_route":None,
                "confirmed_exploit":False,
                "training_eligible":False,
                "official_network_eligible":False,
            })
    if len(out)!=MAX_CASES or len({x["packet_id"] for x in out})!=MAX_CASES:
        raise ProofError("missing or duplicate external review cases")

    return {
        "schema_version":SCHEMA_VERSION,
        "status":STATUS,
        "intent":"SECURITY_REVIEW_GENERAL",
        "advisory":"GHSA-5h86-8mv2-jq9f",
        "external_projects":3,
        "packets":out,
        "external_source_calls":5,
        "external_dependency_profiles":4,
        "actual_third_party_apps_executed":0,
        "accepted_training_pairs":0,
        "independent_human_labels":0,
        "network_eligible":False,
        "public_review_only":True,
        "source_observation_report_sha256":_sha(_canonical(source_report)),
        "dependency_observation_report_sha256":_sha(_canonical(manifest_report)),
        "phase3d_failed_model_not_converted_to_labels":True,
        "reviewer_instructions":"For each immutable source reference verify the cited call, dependency profile, actual installed version, reachable routes and environmental exposure independently. State unresolved when runtime/deployment evidence is missing. Candidate A/B text is unadjudicated, NOT accepted ground truth. Submit reviewer feedback separately; no automatic network submission.",
        "caveat":"All five are newly prepared public-source REVIEW QUESTIONS, not five accepted evaluation rows or security labels. They are selected from already studied upstream applications, NOT a blind external holdout. Alternative requirements profiles must not be collapsed into one deployment."
    }


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Build source-verified independent human review questions; no automatic model labels or submissions")
    p.add_argument("--sources-contract",type=Path,required=True)
    p.add_argument("--dependency-contract",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args(argv)
    try:
        if a.out.exists():
            raise ProofError("will not overwrite an existing review packet")
        source=audit_code(json.loads(a.sources_contract.read_text()))
        dependencies=audit_deps(json.loads(a.dependency_contract.read_text()))
        result=build(source,dependencies)
        a.out.parent.mkdir(parents=True,exist_ok=True)
        a.out.write_bytes(_canonical(result))
        print(json.dumps({
            "status":STATUS,"external_source_review_cases":5,
            "independent_human_labels":0,"accepted_training_pairs":0,
            "network_eligible":False
        },indent=2))
        return 0
    except (ProofError,ValueError,TypeError,KeyError,OSError) as e:
        p.exit(1,f"FALSUM PHASE3E EXTERNAL SECURITY REVIEW QUEUE ERROR: {e}\n")


if __name__=="__main__":
    raise SystemExit(main())
