"""Independent deterministic corpus audit and blinded external review packets.

This module verifies that a draft corpus was generated from its archived source
bytes and the pinned research queue. Passing this check never establishes
security truth, independent review, Telegraph eligibility, or model readiness.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from .advisory_corpus import (CorpusError, build_corpus, parse_osv,
                               validate_corpus, validate_queue)


class ReviewGateError(ValueError):
    """The draft corpus or its review protocol fails closed."""


def _str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def audit_reproducibility(queue: dict, corpus: dict, directory: str | Path) -> dict:
    """Rebuild EVERY row from actual pinned bytes; disallow silent label edits.

    The historical audit verified source integrity and each version label,
    but did not verify the *chosen/rejected wording*, prompt, split, source URL,
    or omission of a pair. All are evaluated here by exact reconstruction.
    """
    issues = validate_queue(queue)
    if issues:
        raise ReviewGateError("queue validation failed: " + "; ".join(issues))
    if not isinstance(corpus, dict):
        raise ReviewGateError("corpus must be a JSON object")
    issues = validate_corpus(corpus, directory)
    if issues:
        raise ReviewGateError("source/label validation failed: " + "; ".join(issues))
    root = Path(directory).resolve()
    docs = {}
    for row in queue["advisories"]:
        advisory_id = row["id"]
        path = (root / "snapshots" / f"{advisory_id}.json").resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ReviewGateError(f"snapshot missing or escapes root: {advisory_id}")
        try:
            raw = path.read_bytes()
            parsed = parse_osv(raw, advisory_id)
        except (OSError, ValueError) as exc:
            raise ReviewGateError(f"cannot parse archived source: {advisory_id}: {exc}") from exc
        docs[advisory_id] = parsed, raw
    try:
        expected = build_corpus(queue, docs)
    except (CorpusError, ValueError, KeyError, TypeError) as exc:
        raise ReviewGateError(f"deterministic rebuilding failed: {exc}") from exc
    # Canonical comparison covers the entire schema including metadata and
    # lengths; list order matters, so moved/omitted/inserted rows are visible.
    if corpus != expected:
        for field in ("schema_version", "status", "upstream_commit", "sources", "cases"):
            if corpus.get(field) != expected.get(field):
                if field == "cases":
                    actual, target = corpus.get(field), expected.get(field)
                    if isinstance(actual, list) and isinstance(target, list):
                        for index in range(min(len(actual), len(target))):
                            if actual[index] != target[index]:
                                raise ReviewGateError(f"case[{index}] differs from source-derived gold; prompts, split, or preference may have been modified")
                        raise ReviewGateError(f"case count/order differs from source-derived gold: {len(actual)} vs {len(target)}")
                raise ReviewGateError(f"{field} differs from source-derived gold")
        raise ReviewGateError("corpus has unexpected fields or non-reproducible structure")
    splits = Counter(x["split"] for x in expected["cases"])
    return {"reproducible": True, "status": "QUARANTINED_DRAFT_ONLY",
            "advisory_sources": len(expected["sources"]), "pairs": len(expected["cases"]),
            "splits": dict(sorted(splits.items())), "human_reviewed": 0,
            "telegraph_eligible": False, "model_training_authorized": False}


def _side(case_id: str) -> str:
    # Deterministically interleave candidates; no manually repeated good-first
    # order that a reviewer might exploit. The source-derived truth is NOT
    # included in the blind packet.
    return "A" if hashlib.sha256(case_id.encode("utf-8")).digest()[0] & 1 else "B"


def blind_review_packet(queue: dict, corpus: dict, directory: str | Path) -> tuple[list[dict], list[dict]]:
    """Return separate blind questions and *private* answer key.

    Caller is responsible for sending ONLY the questions to external reviewers.
    This is not a reviewer identity, eligibility, or security-truth guarantee.
    """
    audit_reproducibility(queue, corpus, directory)
    questions, key = [], []
    for case in corpus["cases"]:
        correct = _side(case["id"])
        a = case["chosen"] if correct == "A" else case["rejected"]
        b = case["rejected"] if correct == "A" else case["chosen"]
        questions.append({"case_id": case["id"], "question": case["prompt"],
                          "candidate_a": a, "candidate_b": b,
                          "source_url": case["source_url"],
                          "review_instructions": "Verify the published advisory and affected-version boundary; select A, B, or uncertain; cite an exact source passage and rationale. Do not infer exploitability.",
                          "response_fields": ["case_id", "preferred", "rationale", "source_quote", "reviewer", "review_date"]})
        key.append({"case_id": case["id"], "expected_preferred": correct,
                    "advisory_id": case["advisory_id"], "expected_status": case["expected_status"],
                    "split": case["split"]})
    return questions, key


def write_review_packet(queue: dict, corpus: dict, source_directory: str | Path,
                        reviewer_directory: str | Path, key_directory: str | Path) -> dict:
    """Create physically separate reviewer and private-key directories.

    Neither location can be nested within the other; a caller should only
    distribute the reviewer directory, never the answer-key directory.
    """
    reviewer = Path(reviewer_directory).resolve()
    private = Path(key_directory).resolve()
    if reviewer == private or reviewer.is_relative_to(private) or private.is_relative_to(reviewer):
        raise ReviewGateError("reviewer and private answer-key directories must not overlap")
    root = Path(source_directory).resolve()
    if reviewer.is_relative_to(root) or private.is_relative_to(root):
        # Keep review packets out of committed source data and prevent copying
        # the key into a future repository artifact accidentally.
        raise ReviewGateError("review outputs must be outside the archived corpus directory")
    questions, key = blind_review_packet(queue, corpus, source_directory)
    if reviewer.exists() and any(reviewer.iterdir()):
        raise ReviewGateError("reviewer directory not empty: refusing overwrite")
    if private.exists() and any(private.iterdir()):
        raise ReviewGateError("private key directory not empty: refusing overwrite")
    reviewer.mkdir(parents=True, exist_ok=True)
    private.mkdir(parents=True, exist_ok=True)
    (reviewer / "BLIND-QUESTIONS.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in questions), encoding="utf-8")
    (private / "DO-NOT-SHARE-ANSWER-KEY.jsonl").write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in key), encoding="utf-8")
    (reviewer / "REVIEW-INSTRUCTIONS.md").write_text(
        "# Independent FALSUM draft review\n\n"
        "These examples are hypothetical and **NOT yet approved or submitted**. "
        "Inspect the immutable advisory source and independently decide whether "
        "candidate A or B correctly classifies the dependency's published version range. "
        "If the evidence is ambiguous, select `uncertain` and explain why. "
        "Do not assess whether a deployed application is actually exploitable from a version boundary alone.\n\n"
        "Return your selections with reviewer identity, calendar date, source passage, "
        "and an original rationale. Do not claim third-party review based on self-reported metadata.\n",
        encoding="utf-8")
    return {"questions": len(questions), "reviewer_directory": str(reviewer),
            "private_answer_key_directory": str(private), "reviewed": 0,
            "telegraph_eligible": False}


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(description="Audit quarantined research material and build blind expert-review packets")
    p.add_argument("queue", type=Path)
    p.add_argument("corpus", type=Path)
    p.add_argument("--audit-only", action="store_true")
    p.add_argument("--reviewer-out", type=Path)
    p.add_argument("--private-key-out", type=Path)
    args = p.parse_args(argv)
    if not args.audit_only and (args.reviewer_out is None or args.private_key_out is None):
        p.error("specify --audit-only or both --reviewer-out and --private-key-out")
    try:
        queue = json.loads(args.queue.read_text(encoding="utf-8"))
        corpus = json.loads(args.corpus.read_text(encoding="utf-8"))
        report = audit_reproducibility(queue, corpus, args.corpus.parent)
        if not args.audit_only:
            report.update(write_review_packet(queue, corpus, args.corpus.parent,
                                              args.reviewer_out, args.private_key_out))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (ReviewGateError, CorpusError, OSError, ValueError) as exc:
        p.exit(1, f"FALSUM REVIEW GATE: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
