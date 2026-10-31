"""Preserve project-level separation between existing inspected diagnostics and new research TRAIN candidates.

Source authenticity is checked by real_fix_corpus + real_fix_replay. This
module strictly controls *which project may appear in which research pool*.
Neither pool is human-adjudicated, sealed, or eligible for model release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .real_fix_corpus import load_queue

STATUS = "PROJECT_DISJOINT_TRAIN_CANDIDATES_AND_INSPECTED_DIAGNOSTICS"
INTENT = "SECURITY_REVIEW_GENERAL"


class PartitionError(ValueError):
    """Training contamination or false eligibility/status would compromise research."""


def _names(rows: list[dict], key: str) -> list[str]:
    names = [r[key].casefold() for r in rows]
    if len(names) != len(set(names)):
        raise PartitionError(f"repeated {key} inside split")
    return names


def validate_pools(train: dict, inspected: dict) -> dict:
    if (not isinstance(train, dict) or not isinstance(inspected, dict)
            or train.get("status") != "PUBLIC_PATCH_SOURCES_DRAFT_UNREVIEWED"
            or inspected.get("status") != "PUBLIC_PATCH_SOURCES_DRAFT_UNREVIEWED"
            or train.get("intent") != INTENT or inspected.get("intent") != INTENT):
        raise PartitionError("invalid research-only status or intent")
    train_rows, inspected_rows = train.get("cases"), inspected.get("cases")
    if (not isinstance(train_rows, list) or not isinstance(inspected_rows, list)
            or len(train_rows) < 3 or len(inspected_rows) < 3):
        raise PartitionError("both pools must include at least three independent projects")
    for r in train_rows + inspected_rows:
        if not isinstance(r, dict):
            raise PartitionError("non-object research source")
    splits = {"train_candidates": train_rows, "inspected_diagnostics": inspected_rows}
    disjoint_fields = ("repository", "advisory", "cve", "commit", "parent", "source_blob", "test_blob")
    for k in disjoint_fields:
        left, right = set(_names(train_rows, k)), set(_names(inspected_rows, k))
        clash = left & right
        if clash:
            raise PartitionError(f"cross-pool {k} leakage: {sorted(clash)}")
    # A source family may have related CWEs across projects; do not fake
    # independence by treating different patches of the SAME repo as disjoint.
    for r in train_rows:
        if (r["id"] in {x["id"] for x in inspected_rows}
                or r["repository"].casefold() in _names(inspected_rows, "repository")):
            raise PartitionError("reused diagnostic case or project")
    return {
        "schema_version": 1, "status": STATUS, "intent": INTENT,
        "source_verified_by_this_function": False,
        "project_separation_verified": True,
        "training_data_authorized": False,
        "evaluation_data_authorized": False,
        "network_eligible": False,
        "human_approved_labels": 0,
        "model_performance_measured": False,
        "sealed_holdout": False,
        "splits": [
            {"name": "train_candidates", "stage": "SOURCE_ONLY_NOT_TRAINABLE",
             "projects": [r["repository"] for r in train_rows],
             "cases": [r["id"] for r in train_rows],
             "rows": len(train_rows), "labels": 0},
            {"name": "inspected_diagnostics", "stage": "PUBLICLY_INSPECTED_NOT_A_SEALED_HOLDOUT",
             "projects": [r["repository"] for r in inspected_rows],
             "cases": [r["id"] for r in inspected_rows],
             "rows": len(inspected_rows), "labels": 0},
        ],
        "notice": "Project-disjoint source-only research inventory. The previously inspected four projects are NOT a hidden independent holdout. No automatic labels, training authorization, security accuracy or network eligibility.",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fail-closed cross-project source segregation for FALSUM")
    p.add_argument("--train", type=Path, required=True)
    p.add_argument("--inspected", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        paths = [x.resolve() for x in (args.train, args.inspected, args.out)]
        if len(set(paths)) < 3 or args.out.exists():
            raise PartitionError("distinct inputs and new output file required")
        tr = load_queue(args.train)
        hold = load_queue(args.inspected)
        result = validate_pools(tr, hold)
        result["source_sha256"] = {
            "train_candidates": hashlib.sha256(args.train.read_bytes()).hexdigest(),
            "inspected_diagnostics": hashlib.sha256(args.inspected.read_bytes()).hexdigest(),
        }
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": result["status"],
            "train_projects": result["splits"][0]["rows"],
            "inspected_projects": result["splits"][1]["rows"],
            "project_separation_verified": True,
            "human_approved_labels": 0,
            "network_eligible": False,
        }, indent=2))
        return 0
    except (PartitionError, ValueError, OSError, TypeError, KeyError) as exc:
        p.exit(1, f"FALSUM PROJECT ISOLATION FAILURE: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
