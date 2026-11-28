"""Phase 5BP: public-provider answer and action quality audit.

This study evaluates six genuine, publicly archived PR Guard response blobs
from one pinned commit.  It does not reproduce or publish payment fields.  A
small source-derived rule oracle is computed from each requested code sample
before the provider answer is scored.  The oracle is deliberately narrow:
SQL string concatenation, shell command construction and dynamic code
execution.  It is a reproducible reference for those code patterns, not human
AppSec gold or a general vulnerability detector.

Unlike a version-token benchmark, the candidate is scored on actual response
claims and actions: target-bound evidence, complete rule coverage, remediation
recommendations and an explicit uncertainty boundary.  Verdict-only and
finding-presence controls are reported beside it.  No answer token or caller
classification selects the result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.request import Request, urlopen

from .phase4l_external_receipt_evidence import git_blob_sha
from .phase5m_real_source_sensitive_model import ROOT


STATUS = "PHASE5BP_PUBLIC_PROVIDER_ANSWER_QUALITY_AUDIT"
FROZEN_STATUS = "PHASE5BP_PUBLIC_PROVIDER_ANSWER_QUALITY_FROZEN"
PROTOCOL = Path("data/phase5bp-public-answer-quality-protocol.json")
REPOSITORY = "anvithagowda098/pr-guard"
COMMIT = "99d2e3c93890a8fc083947bde4f21217516b7a5f"
BASE = f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/"
MAX_BLOB = 2_500_000

SQL_RULE = "sql-injection-risk"
SHELL_RULE = "os-command-injection"
EVAL_RULE = "dynamic-code-execution"
ALL_RULES = frozenset({SQL_RULE, SHELL_RULE, EVAL_RULE})

_SQL_CONCAT = re.compile(r"\b(?:query|execute)\s*\([\s\S]{0,320}\+\s*req\.(?:query|params)\b", re.I)
_SHELL_CONCAT = re.compile(r"\bexec\s*\([\s\S]{0,240}\+\s*req\.", re.I)
_EVAL_INPUT = re.compile(r"\beval\s*\(\s*req\.", re.I)
_REMEDIATION = re.compile(r"parameteri[sz]|allow[- ]list|sanitize|validate|replace|remove|bind", re.I)
_UNCERTAINTY = re.compile(r"bounded|static|manual validation|not prove|not a full|dependency scan", re.I)


class PublicAnswerQualityError(ValueError):
    """Raised when the frozen public evidence or answer contract is invalid."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise PublicAnswerQualityError(reason)


def _strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicAnswerQualityError("malformed public provider JSON") from exc


def _fetch(path: str) -> bytes:
    need(path.startswith("test/fixtures/miner-responses/"), "unapproved provider path")
    url = BASE + path
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "FALSUM-phase5bp/1.0"})
    with urlopen(request, timeout=30) as response:
        need(response.status == 200 and response.geturl() == url, "provider source unavailable or redirected")
        raw = response.read(MAX_BLOB + 1)
    need(0 < len(raw) <= MAX_BLOB, "provider source exceeds fixed byte cap")
    return raw


def frozen_protocol(root: Path = ROOT) -> dict[str, Any]:
    try:
        protocol = _strict_json((root / PROTOCOL).read_bytes())
    except OSError as exc:
        raise PublicAnswerQualityError("Phase 5BP protocol missing") from exc
    need(isinstance(protocol, dict)
         and protocol.get("schema_version") == 1
         and protocol.get("status") == FROZEN_STATUS
         and protocol.get("repository") == REPOSITORY
         and protocol.get("commit") == COMMIT,
         "invalid Phase 5BP protocol identity")
    cases = protocol.get("cases")
    need(isinstance(cases, list) and len(cases) == 6, "Phase 5BP roster changed")
    paths = [row.get("path") for row in cases if isinstance(row, dict)]
    need(len(paths) == 6 and len(set(paths)) == 6, "Phase 5BP paths are not unique")
    selection = protocol.get("selection")
    need(isinstance(selection, dict)
         and selection.get("case_paths_frozen_before_answer_parsing") is True
         and selection.get("reference_rules_derived_from_request_code") is True,
         "Phase 5BP selection contract weakened")
    return protocol


def _target_code(capture: Mapping[str, Any]) -> str:
    request = capture.get("request")
    need(isinstance(request, dict)
         and request.get("method") in ("GET", "POST")
         and request.get("endpoint") in ("/query", "/secreview", "/v1/intent"),
         "provider request envelope is not the expected query shape")
    payload = request.get("payload")
    need(isinstance(payload, dict), "provider request payload missing")
    if isinstance(payload.get("query"), str):
        return payload["query"]
    data = payload.get("input")
    need(isinstance(data, dict) and isinstance(data.get("code"), str),
         "provider request contains no reviewable code")
    return data["code"]


def _reference_rules(code: str) -> frozenset[str]:
    """Derive the narrow reference facts from request code, before answer parsing."""
    rules: set[str] = set()
    if _SQL_CONCAT.search(code):
        rules.add(SQL_RULE)
    if _SHELL_CONCAT.search(code):
        rules.add(SHELL_RULE)
    if _EVAL_INPUT.search(code):
        rules.add(EVAL_RULE)
    return frozenset(rules)


def _answer_text(answer: object) -> str:
    if isinstance(answer, str):
        return answer
    if isinstance(answer, dict):
        return json.dumps(answer, sort_keys=True)
    return ""


def _extract_claims(result: Mapping[str, Any], code: str) -> dict[str, Any]:
    answer = result.get("answer")
    text = _answer_text(answer)
    structured = isinstance(answer, dict)
    findings = answer.get("findings") if structured else []
    if not isinstance(findings, list):
        findings = []
    claimed: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id = finding.get("rule_id")
        if isinstance(rule_id, str):
            claimed.add(rule_id)
    lower = text.casefold()
    negative_verdict = bool(re.search(r"\bsecure\b|no security vulnerabilities|none found", lower)) \
        and not bool(re.search(r"\bvulnerable\b|\binsecure\b", lower))
    if not negative_verdict:
        if "sql injection" in lower or "sql-injection" in lower:
            claimed.add(SQL_RULE)
        if "command injection" in lower or "shell command" in lower:
            claimed.add(SHELL_RULE)
        if "dynamic code" in lower or "remote code execution" in lower or "eval(" in lower:
            claimed.add(EVAL_RULE)

    evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else []
    evidence_records: list[dict[str, Any]] = []
    exact_evidence: list[bool] = []
    for row in evidence:
        if not isinstance(row, dict) or not isinstance(row.get("excerpt"), str):
            continue
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        excerpt = row["excerpt"]
        exact = excerpt in code
        exact_evidence.append(exact)
        evidence_records.append({
            "source_id": row.get("source_id") if isinstance(row.get("source_id"), str) else None,
            "rule_id": metadata.get("rule_id") if isinstance(metadata.get("rule_id"), str) else None,
            "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8")).hexdigest(),
            "matches_target": exact,
        })
    if not structured:
        # Free-text captures may quote the risky sink instead of returning a
        # structured evidence list; only exact target substrings count.
        exact_evidence = [match.group(0) in code for pattern in (_SHELL_CONCAT, _EVAL_INPUT, _SQL_CONCAT)
                          for match in pattern.finditer(text)]
    recommendations = []
    for finding in findings:
        if isinstance(finding, dict) and isinstance(finding.get("recommendation"), str):
            recommendations.append(bool(finding["recommendation"].strip()))
    if not structured and text:
        recommendations = [bool(_REMEDIATION.search(text))] if claimed else []
    uncertainty = result.get("uncertainty") if isinstance(result.get("uncertainty"), list) else []
    uncertainty_text = " ".join(str(row) for row in uncertainty)
    uncertainty_present = bool(uncertainty) or bool(_UNCERTAINTY.search(text))
    finding_bindings: list[dict[str, Any]] = []
    if structured:
        # A source ID may support only one finding for the same rule. Without
        # this one-to-one assignment, duplicate findings can all inherit the
        # same single evidence row and appear individually grounded.
        used_source_ids_by_rule: dict[str, set[str]] = {}
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict) or not isinstance(finding.get("rule_id"), str):
                finding_bindings.append({
                    "finding_index": index,
                    "rule_id": None,
                    "evidence": {"source_ids": [], "matching_source_count": 0, "matches_target": False},
                    "recommendation": {"present": False},
                    "binding_valid": False,
                    "binding_unavailable_reason": "finding_missing_rule_id",
                })
                continue
            rule_id = finding["rule_id"]
            matching_evidence = [
                row for row in evidence_records
                if row["rule_id"] == rule_id and row["matches_target"]
                and isinstance(row["source_id"], str) and row["source_id"]
            ]
            used = used_source_ids_by_rule.setdefault(rule_id, set())
            available = sorted({
                row["source_id"] for row in matching_evidence
                if row["source_id"] not in used
            })
            source_id = available[0] if available else None
            if source_id is not None:
                used.add(source_id)
            recommendation = finding.get("recommendation")
            recommendation_present = isinstance(recommendation, str) and bool(recommendation.strip())
            finding_bindings.append({
                "finding_index": index,
                "rule_id": rule_id,
                "evidence": {
                    "source_ids": [source_id] if source_id is not None else [],
                    "matching_source_count": len({
                        row["source_id"] for row in matching_evidence
                    }),
                    "matches_target": source_id is not None,
                    "one_to_one": source_id is not None,
                },
                "recommendation": {"present": recommendation_present},
                "binding_valid": source_id is not None and recommendation_present,
                "binding_unavailable_reason": None if source_id is not None else "no_distinct_target_bound_source_id",
            })
    else:
        # A natural-language answer can be checked for exact target excerpts,
        # but it has no explicit finding-to-evidence-to-remediation linkage.
        # Keep that limitation visible rather than upgrading a text heuristic
        # into structured binding evidence.
        finding_bindings = [{
            "finding_index": None,
            "rule_id": rule_id,
            "evidence": {"matches_target": False, "matching_source_count": 0, "source_ids": []},
            "recommendation": {"present": False},
            "binding_valid": False,
            "binding_unavailable_reason": "natural_language_answer_has_no_explicit_finding_binding",
        } for rule_id in sorted(claimed)]
    all_claimed_findings_bound = (
        structured
        and len(finding_bindings) == len(findings)
        and all(binding["binding_valid"] for binding in finding_bindings)
    )
    return {
        "surface": "structured" if structured else "free_text",
        "verdict": result.get("verdict") if isinstance(result.get("verdict"), str) else None,
        "claimed_rules": sorted(claimed),
        "finding_count": len(findings),
        "exact_target_evidence_count": sum(exact_evidence),
        "evidence_count": len(exact_evidence),
        "recommendation_count": sum(recommendations),
        "finding_bindings": finding_bindings,
        "all_claimed_findings_bound": all_claimed_findings_bound,
        "finding_binding_mode": "structured_finding_fields" if structured else "natural_language_exact_evidence_only",
        "uncertainty_present": uncertainty_present,
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "target_code_sha256": hashlib.sha256(code.encode("utf-8")).hexdigest(),
    }


def _provider_capture(path: str, expected_blob: str, raw: bytes) -> dict[str, Any]:
    need(git_blob_sha(raw) == expected_blob, f"provider blob changed: {path}")
    capture = _strict_json(raw)
    need(isinstance(capture, dict) and isinstance(capture.get("body"), dict), "provider capture body missing")
    body = capture["body"]
    result = body.get("result")
    need(isinstance(result, dict), "provider result missing")
    code = _target_code(capture)
    # This is deliberately the first semantic operation.  The candidate
    # answer is not consulted when the source-derived reference facts are made.
    reference_rules = _reference_rules(code)
    claims = _extract_claims(result, code)
    claimed_rules = frozenset(claims["claimed_rules"])
    bindings_by_rule = {
        binding["rule_id"]: binding
        for binding in claims["finding_bindings"]
        if isinstance(binding.get("rule_id"), str)
    }
    structured_target_bound = bool(reference_rules) and claims["all_claimed_findings_bound"] and all(
        rule_id in bindings_by_rule and bindings_by_rule[rule_id]["evidence"]["matches_target"]
        for rule_id in reference_rules
    )
    target_bound = (not reference_rules and claims["surface"] == "structured") or (
        bool(reference_rules) and (
            structured_target_bound if claims["surface"] == "structured"
            else claims["exact_target_evidence_count"] >= len(reference_rules)
        )
    )
    claims_match = claimed_rules == reference_rules and (
        claims["surface"] != "structured" or claims["all_claimed_findings_bound"]
    )
    structured_remediation_complete = bool(reference_rules) and claims["all_claimed_findings_bound"] and all(
        rule_id in bindings_by_rule and bindings_by_rule[rule_id]["binding_valid"]
        for rule_id in reference_rules
    )
    remediation_complete = (not reference_rules and claims["uncertainty_present"]) or (
        bool(reference_rules) and (
            structured_remediation_complete if claims["surface"] == "structured"
            else claims["recommendation_count"] >= len(reference_rules)
        )
    )
    scoped = claims["surface"] == "structured" and claims["uncertainty_present"]
    quality_checks = {
        "target_bound_evidence": target_bound,
        "reference_rule_coverage": claims_match,
        "action_or_uncertainty_complete": remediation_complete,
        "scope_boundary_present": scoped,
    }
    quality_passed = sum(quality_checks.values())
    falsum_action = "BLOCK_OR_REMEDIATE" if reference_rules and all(quality_checks.values()) else "HOLD_FOR_REVIEW"
    answer_lower = _answer_text(result.get("answer")).casefold()
    verdict_action = (
        "FLAG" if any(term in answer_lower for term in ("vulnerable", "insecure", "likely"))
        else "CLEAN" if "secure" in answer_lower
        else "HOLD"
    )
    finding_action = "FLAG" if claims["claimed_rules"] else "CLEAN"
    return {
        "path": path,
        "provider_blob_sha1": expected_blob,
        "target_code_sha256": claims["target_code_sha256"],
        "reference": {
            "rules": sorted(reference_rules),
            "provenance": "source-derived narrow static pattern oracle; not human AppSec gold",
        },
        "answer_claims": claims,
        "comparisons": {
            "verdict_only": {"action": verdict_action, "quality_checks": 0},
            "finding_presence_only": {"action": finding_action, "quality_checks": 0},
            "falsum_source_bound": {"action": falsum_action, "quality_checks": quality_passed,
                                    "quality_denominator": len(quality_checks),
                                    "checks": quality_checks,
                                    "individual_finding_bindings": claims["all_claimed_findings_bound"],
                                    "binding_mode": claims["finding_binding_mode"]},
        },
        "provider_capture": {
            "paid_http200_structure_verified": capture.get("paid") is True and capture.get("status") == 200,
            "raw_response_published": False,
            "payment_or_receipt_published": False,
        },
    }


def audit(root: Path = ROOT, *, fetcher=_fetch) -> dict[str, Any]:
    protocol = frozen_protocol(root)
    rows = []
    for case in protocol["cases"]:
        need(isinstance(case, dict) and isinstance(case.get("path"), str)
             and isinstance(case.get("blob_sha1"), str), "invalid Phase 5BP case")
        raw = fetcher(case["path"])
        rows.append(_provider_capture(case["path"], case["blob_sha1"], raw))
    source_bound = [row["comparisons"]["falsum_source_bound"] for row in rows]
    return {
        "schema_version": 1,
        "status": STATUS,
        "protocol": {"path": str(PROTOCOL).replace("\\", "/"), "status": FROZEN_STATUS},
        "provider_source": {"repository": REPOSITORY, "commit": COMMIT},
        "cases": rows,
        "aggregate": {
            "cases": len(rows),
            "structured_surfaces": sum(row["answer_claims"]["surface"] == "structured" for row in rows),
            "free_text_surfaces": sum(row["answer_claims"]["surface"] == "free_text" for row in rows),
            "falsum_quality_checks_passed": sum(row["comparisons"]["falsum_source_bound"]["quality_checks"] for row in rows),
            "falsum_quality_checks_total": sum(row["comparisons"]["falsum_source_bound"]["quality_denominator"] for row in rows),
            "falsum_block_or_remediate": sum(row["comparisons"]["falsum_source_bound"]["action"] == "BLOCK_OR_REMEDIATE" for row in rows),
            "falsum_hold_for_review": sum(row["comparisons"]["falsum_source_bound"]["action"] == "HOLD_FOR_REVIEW" for row in rows),
            "verdict_only_actions": {action: sum(row["comparisons"]["verdict_only"]["action"] == action for row in rows)
                                     for action in ("FLAG", "CLEAN", "HOLD")},
            "finding_presence_actions": {action: sum(row["comparisons"]["finding_presence_only"]["action"] == action for row in rows)
                                          for action in ("FLAG", "CLEAN")},
        },
        "interpretation": {
            "measurement_improvement_claimed": False,
            "human_appsec_gold": False,
            "independent_adoption": False,
            "ranking_improvement": False,
            "summary": "FALSUM evaluates actual public-provider claims and remediation/uncertainty actions with source-bound checks. The controls report verdict and finding presence without those integrity checks. This is a bounded static-pattern quality audit, not human security truth.",
        },
        "limits": [
            "The provider responses are public archived captures, not a sealed blind holdout.",
            "The three-rule reference oracle is source-derived and narrow; it is not independent human AppSec adjudication or complete vulnerability analysis.",
            "Paid/HTTP-200 fields are structural evidence only; settlement and customer adoption are not inferred.",
            "No current registry, live Telegraph request, ACP execution or financial transaction is performed.",
        ],
    }


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit()
        _write_once(args.out, report)
        print(json.dumps({"status": report["status"], "aggregate": report["aggregate"]}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, AssertionError) as exc:
        parser.exit(1, "PHASE5BP PUBLIC ANSWER QUALITY FAILED CLOSED: " + str(exc)[:400] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
