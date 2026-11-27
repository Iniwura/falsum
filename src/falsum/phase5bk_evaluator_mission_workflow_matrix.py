"""Phase 5BK: explicit Evaluators mission and workflow evidence matrix.

The official Season II rules ask Evaluators to show which mission-specific
tests or applications they enable. This module records only two official
mission workflows whose public examples explicitly name SECURITY_REVIEW.
It distinguishes repeatable supporting tests from completed mission delivery,
independent application consumption, ranking change, and adoption. No new
experiment or network action is performed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STATUS = "PHASE5BK_EVALUATOR_MISSION_WORKFLOW_EVIDENCE_MATRIX"
CURRENT_INTENT = "SECURITY_REVIEW"
HISTORICAL_MATERIAL_INTENT = "SECURITY_REVIEW_GENERAL"


class MatrixError(ValueError):
    """Raised when mission evidence is missing, inflated or relabeled."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise MatrixError(reason)


def matrix() -> dict[str, Any]:
    rows = [
        {
            "official_mission": "Model Economy",
            "official_workflow": "GitHub supply-chain verification priced per commit",
            "official_example_intents": ["SECURITY_REVIEW", "VULNERABILITY_TRIAGE", "CODE_REVIEW", "SOCIAL_BOT_DETECTION"],
            "falsum_capability": "Exact package/version advisory-reference gating and response-integrity checks for a PR/dependency security result.",
            "repeatable_supporting_tests": [
                {
                    "command": "PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5z_reviewed_advisory_consumption.py' -v",
                    "evidence": "Phase 5Z source-authenticated application consumption tests",
                    "result": "Original direct captures reduce to target-bound display-only references and suppress known version-inapplicable references.",
                },
                {
                    "command": "PYTHONPATH=src python -m falsum.cli audit-fresh-provider-holdout --out fresh-holdout.json",
                    "evidence": "Phase 5BJ hosted replay",
                    "result": "Fresh public provider evidence: 66 reported references, 38 canonical sources, 27 applicable, 39 fail-closed unknown/insufficient.",
                },
                {
                    "command": "PYTHONPATH=src python -m falsum.cli audit-independent-balanced-holdout --out phase5bm.json",
                    "evidence": "Phase 5BM hosted replay on a new pinned GitHub-reviewed advisory roster",
                    "result": "Balanced 24-case workflow: FALSUM separates 12 applicable from 12 fixed boundaries, removes 12 citation-only false positives, and ties the independent interval baseline.",
                },
            ],
            "workflow_status": "REPEATABLE_SUPPORTING_TEST",
            "independent_application_consumption_verified": False,
            "mission_completed": False,
        },
        {
            "official_mission": "Web3 Native and DeFi",
            "official_workflow": "Machine-proved bug-bounty or smart-contract/dependency security review before capital or payout decisions",
            "official_example_intents": ["SMART_CONTRACT_AUDIT", "VULNERABILITY_TRIAGE", "SECURITY_REVIEW", "CODE_PATCH_VERIFY"],
            "falsum_capability": "Anchor/Rust advisory version boundaries plus original upstream regression execution, with fail-closed unsupported evidence.",
            "repeatable_supporting_tests": [
                {
                    "command": "PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5au_solana_anchor_evidence.py' -v",
                    "evidence": "Phase 5AU authenticated Anchor advisory material",
                    "result": "Twelve exact target/version cases are checked against pinned advisory/source facts; unsupported cases abstain.",
                },
                {
                    "command": "PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5av_solana_anchor_runtime.py' -v",
                    "evidence": "Phase 5AV original Anchor runtime replay",
                    "result": "The pinned fixed revision passes its original tests and the affected revision produces the exact expected security-regression failure with controls preserved.",
                },
            ],
            "workflow_status": "REPEATABLE_SUPPORTING_TEST",
            "independent_application_consumption_verified": False,
            "mission_completed": False,
        },
    ]
    report = {
        "schema_version": 1,
        "status": STATUS,
        "current_official_intent": CURRENT_INTENT,
        "historical_material_intent": HISTORICAL_MATERIAL_INTENT,
        "intent_alias_or_protocol_compatibility_verified": True,
        "authoritative_mapping_sources": [
            "https://github.com/telegraphprotocol/bounties/issues/96",
            "https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md",
        ],
        "maintainer_acceptance_verified": False,
        "registered_evaluator_adapter_verified": False,
        "mission_rows": rows,
        "aggregate": {
            "distinct_official_missions_with_repeatable_supporting_tests": len(rows),
            "distinct_missions_completed": 0,
            "independent_application_consumption_verified": False,
            "ranking_change_claimed": False,
            "independent_customer_adoption_claimed": False,
        },
        "delivery_interpretation": "The matrix supplies repeatable mission-specific supporting tests and valuable coverage. It does not claim completed missions, independent app consumption, a finalized ranking, or customer adoption.",
        "limits": [
            "The test workflows are evaluator-material support, not autonomous Apps & Agents purchases.",
            "Fictional mission-lab scenarios are not used as external customer evidence.",
            "Official sources map SECURITY_REVIEW_GENERAL to the SECURITY_REVIEW family; maintainer acceptance and live adapter registration remain separate external decisions.",
        ],
    }
    validate(report)
    return report


def validate(report: dict[str, Any]) -> None:
    need(isinstance(report, dict) and report.get("status") == STATUS, "invalid mission matrix status")
    need(report.get("current_official_intent") == CURRENT_INTENT
         and report.get("historical_material_intent") == HISTORICAL_MATERIAL_INTENT,
         "intent identities changed")
    need(report.get("intent_alias_or_protocol_compatibility_verified") is True,
         "authoritative Intent family mapping was removed")
    need(isinstance(report.get("authoritative_mapping_sources"), list)
         and set(report["authoritative_mapping_sources"]) == {
             "https://github.com/telegraphprotocol/bounties/issues/96",
             "https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md",
         }, "authoritative mapping sources changed")
    need(report.get("maintainer_acceptance_verified") is False
         and report.get("registered_evaluator_adapter_verified") is False,
         "mapping was conflated with acceptance or registration")
    rows = report.get("mission_rows")
    need(isinstance(rows, list) and [row.get("official_mission") for row in rows] == ["Model Economy", "Web3 Native and DeFi"],
         "mission roster changed or was reordered")
    for row in rows:
        need(row.get("workflow_status") == "REPEATABLE_SUPPORTING_TEST"
             and row.get("independent_application_consumption_verified") is False
             and row.get("mission_completed") is False,
             "supporting test was inflated into mission delivery")
        tests = row.get("repeatable_supporting_tests")
        need(isinstance(tests, list) and len(tests) >= 2,
             "mission-specific test evidence is incomplete")
        for test in tests:
            need(isinstance(test, dict) and isinstance(test.get("command"), str)
                 and isinstance(test.get("evidence"), str)
                 and isinstance(test.get("result"), str),
                 "mission-specific test row is incomplete")
    aggregate = report.get("aggregate")
    need(isinstance(aggregate, dict)
         and aggregate.get("distinct_official_missions_with_repeatable_supporting_tests") == 2
         and aggregate.get("distinct_missions_completed") == 0
         and aggregate.get("independent_application_consumption_verified") is False
         and aggregate.get("ranking_change_claimed") is False
         and aggregate.get("independent_customer_adoption_claimed") is False,
         "mission aggregate was inflated")


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "matrix output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = matrix()
        _write_once(args.out, report)
        print(json.dumps({"status": report["status"], "aggregate": report["aggregate"]}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(1, "PHASE5BK MISSION MATRIX FAILED CLOSED: " + str(exc)[:300] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
