"""Produce a genuinely blinded AppSec reviewer packet for fictional PR cases.

Source inputs remain draft. Expected labels MUST be stored separately from the
public review questions and MUST NOT be submitted as human-reviewed claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from .pr_benchmark import load_verified
from .scenarios import read_casebook


class PRPacketError(ValueError):
    """Reject label leakage, unverified sources, or unsafe output paths."""


def generate(benchmark: Path, casebook: Path) -> tuple[list[dict], list[dict]]:
    data = load_verified(benchmark, casebook)
    book = read_casebook(casebook)
    sources = {s["id"]: s["url"] for s in book["sources"]}
    blinded, private = [], []
    for row in data["cases"]:
        case_id = row["id"]
        side = "A" if hashlib.sha256(case_id.encode("utf-8")).digest()[0] & 1 else "B"
        left = row["contrast_chosen"] if side == "A" else row["contrast_rejected"]
        right = row["contrast_rejected"] if side == "A" else row["contrast_chosen"]
        blinded.append({
            "case_id": case_id,
            "task": "Independently review this fictional PR against the supplied deployment evidence.",
            "prompt_and_diff": row["prompt"],
            "candidate_a": left,
            "candidate_b": right,
            "pinned_security_guidance": [sources[s] for s in row["source_ids"]],
            "response_fields": ["case_id", "preferred", "explanation",
                                "source_quote_or_line", "deployment_assumptions",
                                "reviewer_github", "review_date"],
            "allowed_preferences": ["A", "B", "uncertain"],
            "note": "Do not infer real exploitability; case is fictional and unreviewed.",
        })
        private.append({
            "case_id": case_id,
            "proposed_label": side,
            "split": row["split"],
            "rule_family": row["rule_family"],
            "review_status": "draft",
            "human_validation": False,
        })
    if len(blinded) != 12 or len(private) != 12:
        raise PRPacketError("expected 12 exactly audited draft PR cases")
    return blinded, private


def write_packet(benchmark: Path, casebook: Path,
                 public_dir: Path, private_dir: Path) -> dict:
    root = benchmark.resolve().parent.parent
    public = public_dir.resolve()
    private = private_dir.resolve()
    if (public == private or public.is_relative_to(private)
            or private.is_relative_to(public)):
        raise PRPacketError("public and private directories must be disjoint")
    if public.is_relative_to(root) or private.is_relative_to(root):
        raise PRPacketError("review packet and answer key must be outside repository")
    if public.exists() or private.exists():
        raise PRPacketError("refusing to overwrite existing review output")
    blind, key = generate(benchmark, casebook)
    public.mkdir(parents=True, exist_ok=False)
    private.mkdir(parents=True, exist_ok=False)
    (public / "BLIND-PR-REVIEW.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in blind), encoding="utf-8")
    (private / "DO-NOT-SHARE-PR-ANSWER-KEY.jsonl").write_text(
        "".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in key), encoding="utf-8")
    (public / "REVIEW-INSTRUCTIONS.md").write_text(
        "# Independent FALSUM PR security-review request\n\n"
        "The 12 scenarios are **fictional drafts**, not confirmed vulnerable live projects. "
        "Review the patch and deployment assumptions independently. "
        "Select A, B, or uncertain; cite a specific pinned primary source passage; "
        "explain preconditions, why the rejected option is wrong, and missing evidence. "
        "Provide your own reviewer identity and date. Do not rely on generated labels. "
        "No payment, eligibility, or automatic acceptance is implied.\n\n"
        "Send only the reviewer packet; do not share or commit the PRIVATE answer key.\n",
        encoding="utf-8")
    return {"questions": len(blind), "review_status": "DRAFT_UNREVIEWED",
            "network_eligible": False, "human_reviews": 0,
            "public_directory": str(public),
            "private_key_directory": str(private)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare PR security-review questions for genuinely independent reviewers")
    parser.add_argument("--benchmark", type=Path, default=Path("data/draft-pr-benchmark.json"))
    parser.add_argument("--casebook", type=Path, default=Path("data/draft-scenarios.json"))
    parser.add_argument("--public-out", required=True, type=Path)
    parser.add_argument("--private-out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = write_packet(args.benchmark, args.casebook, args.public_out, args.private_out)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (PRPacketError, OSError, ValueError) as exc:
        parser.exit(1, f"FALSUM PR BLIND REVIEW ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
