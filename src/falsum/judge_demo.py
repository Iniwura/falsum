"""Build one concise, evidence-backed judge-facing demonstration summary."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
STATUS = "FALSUM_UNIFIED_JUDGE_DEMO_SUMMARY"


class JudgeDemoError(ValueError):
    """Raised when committed evidence cannot support the demo summary."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise JudgeDemoError(message)


def _read(root: Path, relative: str) -> dict[str, Any]:
    try:
        value = json.loads((root / relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise JudgeDemoError(f"missing or malformed demo evidence: {relative}") from exc
    need(isinstance(value, dict), f"demo evidence is not an object: {relative}")
    return value


def build(root: Path = ROOT) -> dict[str, Any]:
    answer = _read(root, "data/phase5bp-public-answer-quality-result-v2.json")
    semantics = _read(root, "data/phase5bo-ecosystem-semantics-result.json")
    missions = _read(root, "data/phase5bk-evaluator-mission-workflow-matrix.json")
    pairs = _read(root, "data/phase5bq-anjoman-pair-candidate-packet-v2.json")

    need(answer.get("status") == "PHASE5BP_PUBLIC_PROVIDER_ANSWER_QUALITY_AUDIT", "public answer evidence status changed")
    need(semantics.get("status") == "PHASE5BO_ECOSYSTEM_SEMANTICS_AUDIT", "ecosystem evidence status changed")
    need(missions.get("aggregate", {}).get("distinct_official_missions_with_repeatable_supporting_tests") == 2,
         "mission evidence count changed")
    need(pairs.get("schema_version") == 2
         and pairs.get("intent") == "SECURITY_REVIEW_GENERAL"
         and pairs.get("candidate_pair_count") == 14 and pairs.get("quality_gate_passed") is True
         and pairs.get("submission_state") == "OWNER_REVIEW_REQUIRED_NOT_SUBMITTED",
         "pair preparation is not a non-submitted quality-gated packet")

    answer_aggregate = answer["aggregate"]
    semantics_policy = semantics["policies"]["improved_candidate"]
    structured_policy = semantics["policies"]["structured_claim_action_selection"]
    return {
        "schema_version": 1,
        "status": STATUS,
        "headline": "FALSUM binds security answers to exact source, target and action, then holds incomplete evidence.",
        "sixty_second_route": [
            {
                "step": 1,
                "title": "Actual public-provider answers",
                "command": "PYTHONPATH=src python -m falsum.cli audit-public-answer-quality --out reviewer-answer-quality.json",
                "result": f"{answer_aggregate['falsum_quality_checks_passed']}/{answer_aggregate['falsum_quality_checks_total']} source-bound checks pass; {answer_aggregate['falsum_block_or_remediate']}/6 complete actions are supported and {answer_aggregate['falsum_hold_for_review']}/6 are held.",
            },
            {
                "step": 2,
                "title": "Native version semantics",
                "command": "PYTHONPATH=src FALSUM_PHASE5BO_NODE_PATH=.phase5bo-node/node_modules python -m falsum.cli audit-ecosystem-semantics --out ecosystem.json",
                "result": f"{semantics_policy['correct']}/{semantics_policy['denominator']} candidate decisions and {structured_policy['correct']}/{structured_policy['denominator']} structured claim/actions resolve against immutable snapshots.",
            },
            {
                "step": 3,
                "title": "Mission usefulness",
                "command": "PYTHONPATH=src python -m falsum.cli audit-evaluator-mission-matrix --out missions.json",
                "result": "Two distinct official mission workflows have repeatable supporting tests; neither is presented as completed delivery or adoption.",
            },
        ],
        "competitive_advantage": [
            "Exact source, target, transport and response-identity binding.",
            "PEP 440 and strict SemVer prerelease/disjoint-interval semantics with immutable replay.",
            "Explicit hold/abstain behavior for malformed or unsupported evidence.",
            "Actual answer-claim, evidence-anchor, remediation-action and uncertainty checks.",
        ],
        "prepared_material": {
            "candidate_pairs": pairs["candidate_pair_count"],
            "quality_gate_passed": pairs["quality_gate_passed"],
            "submission_state": pairs["submission_state"],
            "intent": pairs["intent"],
            "upload_preview": "data/phase5bq-anjoman-upload-preview-v2.jsonl",
        },
        "limits": [
            "No human AppSec gold, independent customer adoption, live evaluator registration or ranking change is claimed.",
            "The public-provider oracle is narrow and source-derived, not a complete vulnerability adjudication.",
            "ACP and financial execution remain suspended.",
        ],
    }


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(),
         "judge demo output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        report = build()
        if args.out is not None:
            _write_once(args.out, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(1, "FALSUM UNIFIED JUDGE DEMO FAILED CLOSED: " + str(exc)[:500] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
