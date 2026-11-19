"""Re-run TWO previously researched source families beyond Phase 4U's four fixes.

Strict cross-family REPLAY, never a blind holdout, a model quality score,
an independent security review, or a newly accepted Telegraph evaluation.
The runner's GitHub Actions jobs actually import installed historical libraries;
this report alone does not attest to the origin of arbitrary user-provided JSON.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from .phase3h_starlette_runtime import (
    CASE as STARLETTE_CASE, REPO as STARLETTE_REPO,
    compare as starlette_compare, verify_source_queue,
)
from .phase3i_requests_runtime import (
    CASE as REQUESTS_CASE, REPOSITORY as REQUESTS_REPO,
    compare as requests_compare, pin_queue,
)
from .source_review_witness_gate import validated_index

STATUS = "PHASE4Y_TWO_PREVIOUSLY_RESEARCHED_CROSS_FAMILY_REPLAYS_NOT_BLIND_GENERALIZATION"
MAX_REPORT_BYTES = 80_000


class ReplayError(ValueError):
    """Historical execution or source provenance did not meet the exact gate."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ReplayError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate JSON key in untrusted runtime report")
        value[key] = item
    return value


def read_json(path: Path) -> tuple[dict, str]:
    require(path.is_file() and not path.is_symlink(), "missing or symlinked input")
    require(0 < path.stat().st_size <= MAX_REPORT_BYTES, "missing/oversized input")
    raw = path.read_bytes()
    try:
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except (ValueError, UnicodeError) as exc:
        raise ReplayError("invalid JSON runtime input") from exc
    require(isinstance(data, dict), "runtime input must be a JSON object")
    return data, sha(raw)


def check(
    *,
    source_index: bytes,
    source_lock: bytes,
    starlette_before: dict,
    starlette_after: dict,
    requests_before: dict,
    requests_after: dict,
    starlette_queue: Path,
    requests_queue: Path,
) -> dict:
    """Cross-family consistency check of four separately executed version reports."""
    source = validated_index(source_index, source_lock)
    require(len(source) == 4, "four original executed stages missing")
    require(len({row["repository"] for row in source.values()}) == 3,
            "original source-project cardinality changed")
    verify_source_queue(starlette_queue)
    pin_queue(requests_queue)
    s = starlette_compare(starlette_before, starlette_after)
    r = requests_compare(requests_before, requests_after)

    require(s["case_id"] == STARLETTE_CASE and
            s["controlled_sibling_visible_before"] is True and
            s["controlled_sibling_blocked_after"] is True and
            s["unchanged_safe_and_negative_controls"] == 3 and
            s["trained_model_tested"] is False and
            s["independently_validated_expert_labels"] == 0 and
            s["network_eligible"] is False, "Starlette before/after control gate failed")
    require(r["case_id"] == REQUESTS_CASE and
            r["historical_https_proxy_header_before"] is True and
            r["https_proxy_header_after_fix"] is False and
            r["stable_http_credentialed_proxy_header"] is True and
            r["stable_other_negative_controls"] == 3 and
            r["outbound_network_calls"] == 0 and
            r["model_scored"] is False and
            r["independently_approved_labels"] == 0 and
            r["network_eligible"] is False, "Requests before/after control gate failed")
    source_repos = {row["repository"].lower() for row in source.values()}
    add_repos = {STARLETTE_REPO.lower(), REQUESTS_REPO.lower()}
    require(len(add_repos) == 2 and not source_repos.intersection(add_repos),
            "out-of-four cases are not distinct upstream projects")

    return {
        "schema_version": 1,
        "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "evidence_basis": "REAL_INSTALLED_HISTORICAL_LIBRARY_METHODS_AND_PINNED_SOURCE_QUEUES",
        "existing_source_executed_stages": 4,
        "existing_source_projects": 3,
        "cross_family_replayed_boundaries": 2,
        "cross_family_distinct_projects": 2,
        "total_distinct_historical_projects_across_two_evidence_methods": 5,
        "methods_are_not_identical": True,
        "out_of_four_cases": [
            {
                "id": STARLETTE_CASE,
                "repository": STARLETTE_REPO,
                "affected_version": "0.26.1",
                "fixed_version": "0.27.0",
                "observed_safety_boundary": "same-prefix StaticFiles sibling containment",
                "reversal_verified": True,
                "unchanged_controls": 3,
                "no_external_network_requests": True,
            },
            {
                "id": REQUESTS_CASE,
                "repository": REQUESTS_REPO,
                "affected_version": "2.30.0",
                "fixed_version": "2.31.0",
                "observed_safety_boundary": "HTTPS proxy authorization header reconstruction",
                "reversal_verified": True,
                "unchanged_controls": 4,
                "no_external_network_requests": True,
            },
        ],
        "already_studied_in_phases_3h_and_3i": True,
        "genuinely_pre_registered_unseen_projects_tested": 0,
        "source_witness_checker_extended_to_these_cases": False,
        "novel_cases_where_checker_correctly_recognizes_source_facts": 0,
        "independent_human_appsec_labels": 0,
        "registered_telegraph_evaluator": False,
        "new_anjoman_eligible_rows": 0,
        "trained_model_scored_on_new_cases": False,
        "trained_model_generalization_proven": False,
        "official_h2_entry_submitted": False,
        "limitations": (
            "This replays two real but previously researched installed-library version contrasts "
            "outside the Phase 4U four-case source-witness index. It establishes additional "
            "bounded historical source behavior only. It is not a fresh blind holdout, "
            "proof of natural-language security-evaluator accuracy, a new reviewer label, "
            "a network-scoring adapter, or proof of production exploitability. "
            "An untrusted JSON report alone cannot prove its own real execution; "
            "use the actual GitHub Actions job logs and upstream package installs."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare four real installed-version reports across two historical source families")
    for name in (
        "source-index", "source-lock", "starlette-before", "starlette-after",
        "requests-before", "requests-after", "starlette-queue", "requests-queue", "out",
    ):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args(argv)
    try:
        inputs = [
            args.source_index, args.source_lock, args.starlette_before,
            args.starlette_after, args.requests_before, args.requests_after,
            args.starlette_queue, args.requests_queue,
        ]
        require(not args.out.exists() and not args.out.is_symlink() and
                args.out.resolve() not in {x.resolve() for x in inputs},
                "output must be new and must not overwrite input")
        s_before, h1 = read_json(args.starlette_before)
        s_after, h2 = read_json(args.starlette_after)
        r_before, h3 = read_json(args.requests_before)
        r_after, h4 = read_json(args.requests_after)
        index_raw = args.source_index.read_bytes()
        lock_raw = args.source_lock.read_bytes()
        result = check(
            source_index=index_raw, source_lock=lock_raw,
            starlette_before=s_before, starlette_after=s_after,
            requests_before=r_before, requests_after=r_after,
            starlette_queue=args.starlette_queue, requests_queue=args.requests_queue,
        )
        result["input_report_sha256"] = {
            "starlette_before": h1, "starlette_after": h2,
            "requests_before": h3, "requests_after": h4,
        }
        result["existing_four_stage_source_index_sha256"] = sha(index_raw)
        result["existing_four_stage_source_lock_sha256"] = sha(lock_raw)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, sort_keys=True)
            f.write("\n")
        print(json.dumps({
            "status": result["status"], "out_of_four_replayed": 2,
            "genuine_new_blind_holdouts": 0, "independent_human_gold": 0,
            "output": str(args.out),
        }, sort_keys=True))
        return 0
    except (ReplayError, ValueError, KeyError, TypeError, OSError) as exc:
        p.exit(1, "FALSUM PHASE4Y CROSS-FAMILY REPLAY FAILED: " + str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
