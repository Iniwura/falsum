"""Prepare source-backed Anjoman preference-pair candidates without submission.

The packet is an owner-review artifact, not an eligibility claim.  Every row is
derived from the immutable Phase5BO advisory and registry snapshots, carries
source and version provenance, and is rejected if the reference resolver no
longer reproduces the frozen label.  No network upload, wallet operation or
maintainer acceptance is attempted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from .phase5bo_ecosystem_semantics import (
    APPLICABLE,
    INAPPLICABLE,
    _action_for,
    _available_versions,
    _load_evidence,
    _load_protocol,
    _reference_status,
)


ROOT = Path(__file__).resolve().parents[2]
PROTOCOL = Path("data/phase5bo-ecosystem-semantics-protocol.json")
STATUS = "PHASE5BQ_ANJOMAN_PAIR_CANDIDATE_PACKET"
CURRENT_INTENT = "SECURITY_REVIEW"
HISTORICAL_INTENT = "SECURITY_REVIEW_GENERAL"


class PairPreparationError(ValueError):
    """Raised when a candidate pair cannot be proven source-backed."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise PairPreparationError(message)


def _answer(decision: str, ecosystem: str, package: str, version: str, advisory_id: str) -> dict[str, str]:
    action = _action_for(decision)
    if decision == APPLICABLE:
        text = (
            f"{ecosystem}:{package}@{version} falls inside the published affected interval for "
            f"{advisory_id}. Block or upgrade for this advisory, while limiting the claim to "
            "version applicability rather than exploitability."
        )
    elif decision == INAPPLICABLE:
        text = (
            f"{ecosystem}:{package}@{version} is outside the published affected interval for "
            f"{advisory_id}. Take no action for this advisory alone, while checking other "
            "advisories and application-specific evidence; this is a version-applicability "
            "claim and does not establish exploitability."
        )
    else:
        text = (
            f"The published evidence for {ecosystem}:{package}@{version} and {advisory_id} "
            "cannot be resolved safely. Abstain and request a supported range or exact-version "
            "source; no exploitability claim is made."
        )
    return {
        "decision": decision,
        "action": action,
        "scope": "version_applicability_only",
        "text": text,
    }


def _wrong_decision(decision: str) -> str:
    if decision == APPLICABLE:
        return INAPPLICABLE
    if decision == INAPPLICABLE:
        return APPLICABLE
    return APPLICABLE


def _pair_id(case: dict[str, Any], advisory_meta: dict[str, Any], registry_meta: dict[str, Any]) -> str:
    material = "|".join((
        str(case["case_id"]),
        str(advisory_meta.get("sha256")),
        str(registry_meta.get("sha256")),
        str(case["target"]["version"]),
    ))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def prepare(root: Path = ROOT) -> dict[str, Any]:
    protocol = _load_protocol(root)
    advisories, registries = _load_evidence(root, protocol)
    rows: list[dict[str, Any]] = []
    seen_questions: set[str] = set()
    seen_pairs: set[str] = set()

    for case in protocol["cases"]:
        target = case["target"]
        advisory_id = case["advisory_id"]
        ecosystem = target["ecosystem"]
        package = target["package"]
        version = target["version"]
        advisory_meta = protocol["advisories"][advisory_id]
        registry_key = f"{ecosystem}-{package}"
        registry_meta = protocol["registries"][registry_key]
        advisory = advisories[advisory_id]
        registry = registries[registry_key]

        question = (
            f"For {ecosystem}:{package}@{version}, does advisory {advisory_id} apply "
            "according to the published version evidence?"
        )
        normalized_question = " ".join(question.casefold().split())
        need(normalized_question not in seen_questions, "duplicate normalized question")
        seen_questions.add(normalized_question)

        reference = case["reference"]["label"]
        reproduced = _reference_status(advisory, ecosystem, package, version)
        need(reproduced == reference, f"frozen reference label does not reproduce: {case['case_id']}")
        available = _available_versions(ecosystem, registry)
        need(version in available, f"candidate version missing from registry snapshot: {package}@{version}")

        pair_id = _pair_id(case, advisory_meta, registry_meta)
        need(pair_id not in seen_pairs, "duplicate pair fingerprint")
        seen_pairs.add(pair_id)
        better = _answer(reference, ecosystem, package, version, advisory_id)
        worse = _answer(_wrong_decision(reference), ecosystem, package, version, advisory_id)
        quality_checks = {
            "advisory_source_pinned": isinstance(advisory_meta.get("sha256"), str) and len(advisory_meta["sha256"]) == 64,
            "registry_source_pinned": isinstance(registry_meta.get("sha256"), str) and len(registry_meta["sha256"]) == 64,
            "advisory_identity_verified": advisory.get("id") == advisory_id,
            "version_exists_in_immutable_registry_snapshot": version in available,
            "reference_label_reproduced": reproduced == reference,
            "better_and_worse_are_distinct": better["decision"] != worse["decision"] and better["text"] != worse["text"],
            "both_answers_are_scope_limited": better["scope"] == worse["scope"] == "version_applicability_only",
            "scope_disclaims_exploitability": (
                "exploitability" in better["text"] and "exploitability" in worse["text"]
                and "version" in better["text"] and "version" in worse["text"]
            ),
        }
        need(all(quality_checks.values()), f"pair quality gate failed: {case['case_id']}")
        rows.append({
            "pair_id": pair_id,
            "question": question,
            "normalized_question": normalized_question,
            "better_answer": better,
            "worse_answer": worse,
            "reference_label": reference,
            "provenance": {
                "advisory_id": advisory_id,
                "advisory_source_url": advisory_meta["source_url"],
                "advisory_source_sha256": advisory_meta["sha256"],
                "advisory_snapshot": advisory_meta["snapshot"],
                "registry_source_url": registry_meta["source_url"],
                "registry_source_sha256": registry_meta["sha256"],
                "registry_snapshot": registry_meta["snapshot"],
                "ecosystem": ecosystem,
                "package": package,
                "version": version,
            },
            "deduplication": {
                "normalization": "casefold and collapse whitespace",
                "unique_question_in_packet": True,
                "unique_pair_fingerprint_in_packet": True,
            },
            "quality_checks": quality_checks,
            "submission_state": "CANDIDATE_NOT_SUBMITTED",
            "human_adjudicated": False,
            "network_eligible": False,
        })

    report = {
        "schema_version": 1,
        "status": STATUS,
        "intent": CURRENT_INTENT,
        "historical_material_intent": HISTORICAL_INTENT,
        "protocol": str(PROTOCOL).replace("\\", "/"),
        "source_policy": "Pinned GitHub-reviewed advisory and immutable package-registry snapshots only",
        "candidate_pair_count": len(rows),
        "quality_gate_passed": True,
        "deduplication_passed": len(rows) == len(seen_questions) == len(seen_pairs),
        "submission_state": "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED",
        "human_adjudication": False,
        "network_eligibility": False,
        "rows": rows,
        "limits": [
            "These are source-backed candidate pairs, not accepted Anjoman material or maintainer-approved labels.",
            "The preference contrast is a deterministic version-applicability pair and is not human AppSec gold.",
            "No row is uploaded, signed, paid, or presented as independent adoption.",
        ],
    }
    validate(report)
    return report


def validate(report: dict[str, Any]) -> None:
    need(report.get("status") == STATUS, "invalid candidate packet status")
    rows = report.get("rows")
    need(isinstance(rows, list) and rows and report.get("quality_gate_passed") is True,
         "candidate packet is empty or not quality-gated")
    need(report.get("submission_state") == "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED"
         and report.get("human_adjudication") is False
         and report.get("network_eligibility") is False,
         "candidate packet was inflated into acceptance")
    pair_ids = [row.get("pair_id") for row in rows]
    questions = [row.get("normalized_question") for row in rows]
    need(len(pair_ids) == len(set(pair_ids)) and len(questions) == len(set(questions)),
         "candidate packet contains duplicate pairs")
    for row in rows:
        need(row.get("submission_state") == "CANDIDATE_NOT_SUBMITTED"
             and row.get("human_adjudicated") is False
             and row.get("network_eligible") is False,
             "row was inflated into acceptance")
        need(all(row.get("quality_checks", {}).values()), "row quality gate failed")
        need(row.get("better_answer", {}).get("decision") != row.get("worse_answer", {}).get("decision"),
             "better and worse answers collapse")
        need("answer_token" not in json.dumps(row, sort_keys=True), "opaque answer token leaked into pair packet")


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(),
         "pair packet output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = prepare()
        _write_once(args.out, report)
        print(json.dumps({"status": report["status"], "candidate_pair_count": report["candidate_pair_count"],
                          "quality_gate_passed": report["quality_gate_passed"],
                          "submission_state": report["submission_state"]}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(1, "PHASE5BQ ANJOMAN PAIR PREPARATION FAILED CLOSED: " + str(exc)[:500] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
