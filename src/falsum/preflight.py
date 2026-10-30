"""Research-only diagnostic for FALSUM preference data.

No result from this module constitutes human review, a valid source verdict,
Telegraph upload eligibility, or authorization to train/publish a model.
The upstream gate must run independently on eventual reviewed material.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .scenarios import read_casebook, verify_source_snapshots

# Read directly from the pinned Telegraph V2 reference trainer source.
# These are a LOCAL early-warning mirror, not the official gate itself.
UPSTREAM_MIN_PAIRS = 50  # 1 distinct negative / n <= MAX_SINGLE_REJECTED = 0.02
UPSTREAM_MIN_UNIQUE_NEGATIVES = 0.80
UPSTREAM_MAX_LENGTH_SHORTCUT = 0.65
UPSTREAM_MAX_IDENTICAL_FRACTION = 0.01
UPSTREAM_MAX_REPEATED_NEGATIVE_SHARE = 0.02


class PreflightError(ValueError):
    pass


def render_for_judgment(prompt: str, answer: str) -> str:
    """Exact V2 RenderForJudgment template; tokenizer conformance is separate."""
    return f"### Task:\n{prompt}\n\n### Answer:\n{answer}"


def draft_triplets(book: dict[str, Any], split: str = "train") -> list[dict[str, str]]:
    """Extract *diagnostic-only* triplets from structurally valid draft scenarios."""
    if split not in {"train", "validation", "holdout"}:
        raise PreflightError("unknown split")
    cases = [row for row in book["cases"] if row["split"] == split]
    if not cases:
        raise PreflightError(f"no cases for {split}")
    return [{key: row[key] for key in ("prompt", "chosen", "rejected")} for row in cases]


def diagnostic_metrics(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Non-ML early warnings; the official gate additionally tests style tells."""
    n = len(rows)
    if not n:
        raise PreflightError("no rows")
    negatives = Counter(row["rejected"].strip() for row in rows)
    longer = sum(len(row["chosen"]) > len(row["rejected"]) for row in rows)
    equal = sum(len(row["chosen"]) == len(row["rejected"]) for row in rows)
    length_shortcut = max((longer + 0.5 * equal) / n, 1 - (longer + 0.5 * equal) / n)
    identical = sum(row["chosen"].strip() == row["rejected"].strip() for row in rows)
    single_share = max(negatives.values()) / n
    unique_share = len(negatives) / n
    failures = []
    if n < UPSTREAM_MIN_PAIRS:
        failures.append(f"{n} training pairs; at least {UPSTREAM_MIN_PAIRS} needed for the official 2% single-negative cap")
    if single_share > UPSTREAM_MAX_REPEATED_NEGATIVE_SHARE:
        failures.append(f"single rejected-answer share {single_share:.1%} exceeds 2%")
    if unique_share < UPSTREAM_MIN_UNIQUE_NEGATIVES:
        failures.append(f"distinct rejected-answer share {unique_share:.1%} below 80%")
    if length_shortcut > UPSTREAM_MAX_LENGTH_SHORTCUT:
        failures.append(f"shorter/longer answer shortcut achieves {length_shortcut:.1%} (>65%)")
    if identical / n > UPSTREAM_MAX_IDENTICAL_FRACTION:
        failures.append("chosen/rejected identity rate exceeds 1%")
    return {
        "n": n,
        "distinct_rejected": len(negatives),
        "single_rejected_share": round(single_share, 4),
        "unique_rejected_share": round(unique_share, 4),
        "length_shortcut_accuracy": round(length_shortcut, 4),
        "identical_pairs": identical,
        "preflight_clear": not failures,
        "failures": failures,
        "official_gate_ran": False,
    }


def preflight_casebook(path: str | Path, *, diagnostic_dir: str | Path | None = None) -> dict[str, Any]:
    """Verify pinned sources, provide an honest report, optionally write quarantined triplets.

    Never writes a training directory, changes reviewed flags, or labels rows
    Telegraph-eligible. The diagnostic file is for the *official --check-data*
    command and must not be sent to Anjoman or used with a training command.
    """
    path = Path(path)
    book = read_casebook(path)
    issues = verify_source_snapshots(book, path.parent)
    if issues:
        raise PreflightError("source integrity failure: " + "; ".join(issues))
    rows = draft_triplets(book)
    stats = diagnostic_metrics(rows)
    stats.update({
        "casebook": path.name,
        "total_cases": len(book["cases"]),
        "splits": dict(sorted(Counter(row["split"] for row in book["cases"]).items())),
        "categories": dict(sorted(Counter(row["category"] for row in book["cases"]).items())),
        "independently_reviewed": sum(row["review_status"] == "reviewed" for row in book["cases"]),
        "pinned_source_excerpts": sum(s["state"] == "pinned" for s in book["sources"]),
        "human_review_required": True,
        "network_eligible": False,
        "model_training_authorized": False,
        "input_format": "### Task:\\n<prompt>\\n\\n### Answer:\\n<answer>",
        "max_model_tokens": 512,
        "tokenizer_conformance_checked": False,
    })
    if diagnostic_dir is not None:
        directory = Path(diagnostic_dir)
        directory.mkdir(parents=True, exist_ok=True)
        triplet_path = directory / "DRAFT-ONLY-NOT-FOR-TRAINING.jsonl"
        payload = "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows)
        triplet_path.write_text(payload, encoding="utf-8")
        stats["diagnostic_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        (directory / "STATUS-NOT-ELIGIBLE.json").write_text(json.dumps(stats, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return stats
