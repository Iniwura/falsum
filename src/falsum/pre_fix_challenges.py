"""Remediation-withheld real-code challenges. Never training labels or hidden holdouts.

Each prompt contains ONLY a bounded excerpt of source code from a cryptographically
verified PRE-FIX revision. Fixes, tests, advisory IDs, project/commit names, and
deployment judgments live in a distinct provenance artifact, never in prompts.
The public code is traceable: this is not a sealed independent benchmark.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from .real_fix_replay import (
    HUNK, ReplayError, fetch_raw, raw_url, verify_report, git_blob_sha,
)

STATUS = "UNREVIEWED_PUBLIC_PRE_FIX_CHALLENGE_NO_ANSWERS"
MAX_SEGMENT_LINES = 70
MAX_PROMPT_BYTES = 4300
MAX_HUNKS_PER_CASE = 12
FENCE = chr(96) * 3
ADVISORY_ID = re.compile(r"(?i)\\b(?:GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|CVE-\\d{4}-\\d{4,})\\b")
LANGUAGES = {".py": "python", ".js": "javascript", ".ts": "typescript", ".go": "go",
             ".rs": "rust", ".rb": "ruby"}


class ChallengeError(ValueError):
    """Refuse leaked remediation details, fake historical bytes, or oversized inputs."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def parent_regions(parent: bytes, patch: str, *, flank: int = 0) -> list[dict]:
    """Select exact old-line windows around *every* changed source hunk.

    Never uses + lines; all displayed material is sliced from the actual
    pinned parent bytes. Overlapping windows merge; unrelated hunks do not.
    Fails rather than truncating oversized spans.
    """
    if type(flank) is not int or not 0 <= flank <= 8:
        raise ChallengeError("flank out of range")
    try:
        full = parent.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ChallengeError("parent source must be UTF-8") from exc
    if full and not full.endswith("\n"):
        raise ChallengeError("source must have newline-terminated lines")
    lines = full.splitlines()
    heads = []
    for line in patch.splitlines():
        match = HUNK.fullmatch(line)
        if match:
            old_start = int(match.group(1))
            old_count = int(match.group(2) or 1)
            if old_count < 1 or old_start < 1 or old_start + old_count - 1 > len(lines):
                raise ChallengeError("invalid original hunk line range")
            left = max(1, old_start - flank)
            right = min(len(lines), old_start + old_count - 1 + flank)
            heads.append((left, right))
    if not heads or len(heads) > MAX_HUNKS_PER_CASE:
        raise ChallengeError("no bounded old-file hunks")
    merged = []
    for left, right in heads:
        if merged and left <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], right))
        else:
            merged.append((left, right))
    windows = []
    for left, right in merged:
        if right - left + 1 > MAX_SEGMENT_LINES:
            raise ChallengeError("source region exceeds line budget; refuse hidden truncation")
        chunk = "".join(f"{n:>5} | {lines[n - 1]}\n" for n in range(left, right + 1))
        windows.append({"first_line": left, "last_line": right,
                        "numbered_source": chunk,
                        "raw_source": "\n".join(lines[left-1:right]) + "\n"})
    return windows


def build_challenges(report: dict, reader: Callable[[str], bytes] | None = None) -> tuple[dict, dict]:
    if reader is None:
        reader = fetch_raw
    # Full cross-check of commit SHA, parent, complete replay and ALL file blobs.
    replayed = verify_report(report, reader)
    verified_rows = replayed["verified"]
    evidence_rows = report["cases"]
    if len(verified_rows) != len(evidence_rows):
        raise ChallengeError("source verification count mismatch")
    public = []
    private_provenance = []
    for source, verified in zip(evidence_rows, verified_rows):
        if source["id"] != verified["case_id"]:
            raise ChallengeError("reordered or changed source evidence")
        base = reader(raw_url(source["repository"], source["parent"], source["source"]["file_path"]))
        if git_blob_sha(base) != verified["files"]["source"]["parent_git_blob"]:
            raise ChallengeError("parent changed since cryptographic replay")
        windows = parent_regions(base, source["source"]["patch"])
        language = LANGUAGES.get(Path(source["source"]["file_path"]).suffix.lower())
        if language is None:
            raise ChallengeError("unsupported code language for source-review challenge")
        for index, window in enumerate(windows):
            if ADVISORY_ID.search(window["raw_source"]):
                raise ChallengeError("pre-fix source includes public advisory identifier; unsafe label shortcut")
            ident = _sha(f'{source["repository"]}:{source["parent"]}:{source["source"]["file_path"]}:{index}'.encode())[:20]
            question = (
                "Review the following original code excerpt for concrete security concerns. "
                "State missing deployment preconditions and avoid unsupported exploitability claims.\n\n"
                "Source excerpt:\n"
                + FENCE + language + "\n" + window["raw_source"] + FENCE
            )
            if len(question.encode("utf-8")) > MAX_PROMPT_BYTES:
                raise ChallengeError("challenge exceeds text budget; no silent truncation")
            # NO filenames, project names, vulnerability family, GHSA/CVE, patch,
            # corrected source, regression tests, expected finding, or preference.
            public.append({"challenge_id": ident, "prompt": question})
            private_provenance.append({
                "challenge_id": ident,
                "case_id": source["id"], "repository": source["repository"],
                "parent": source["parent"], "fix_commit": source["commit"],
                "source_path": source["source"]["file_path"],
                "parent_source_blob": verified["files"]["source"]["parent_git_blob"],
                "fix_source_blob": verified["files"]["source"]["post_fix_git_blob"],
                "source_lines": [window["first_line"], window["last_line"]],
                "advisory_url": source["advisory_url"], "fix_commit_url": source["commit_url"],
                "source_patch_sha256": source["source"]["sha256"],
                "regression_test_patch_sha256": source["regression_test"]["sha256"],
                "independent_review_status": "NOT_REVIEWED",
                "eligible": False, "human_label": None,
            })
    if not public or len({r["challenge_id"] for r in public}) != len(public):
        raise ChallengeError("empty or colliding challenges")
    if set(k for r in public for k in r) != {"challenge_id", "prompt"}:
        raise ChallengeError("public model prompts contain forbidden answer metadata")
    public_manifest = {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "model_training_authorized": False, "evaluation_authorized": False,
        "network_eligible": False, "independent_human_reviews": 0,
        "sealed_holdout": False,
        "tokenizer_512_verified": False,
        "source_cases_sha256": report["cases_sha256"],
        "prompts": public,
        "notice": "Public, pre-fix excerpts; NO labels. Not a sealed test, valid scorecard, or eligible training corpus.",
    }
    # A separate artifact links prompts to real fixes for independent reviewers.
    provenance_manifest = {
        "schema_version": 1, "status": "REMEDIATION_EVIDENCE_WITHHELD_FROM_MODEL_INPUT",
        "source_cases_sha256": report["cases_sha256"],
        "public_prompt_sha256": _sha(_canonical(public_manifest)),
        "model_training_authorized": False, "network_eligible": False,
        "independent_human_reviews": 0, "records": private_provenance,
        "notice": "Provenance is PUBLIC and traceable, not a secret or hidden test key. Never place these fields into a model-scoring prompt.",
    }
    return public_manifest, provenance_manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create public pre-fix-only prompts without remediation or answer leakage")
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--public-out", type=Path, required=True)
    parser.add_argument("--provenance-out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if (args.public_out.resolve() == args.provenance_out.resolve()
                or args.public_out.exists() or args.provenance_out.exists()):
            raise ChallengeError("output paths must differ and must not already exist")
        report = json.loads(args.evidence.read_text(encoding="utf-8"))
        public, provenance = build_challenges(report)
        args.public_out.parent.mkdir(parents=True, exist_ok=True)
        args.provenance_out.parent.mkdir(parents=True, exist_ok=True)
        args.public_out.write_bytes(_canonical(public))
        args.provenance_out.write_bytes(_canonical(provenance))
        print(json.dumps({
            "status": public["status"], "public_prompts": len(public["prompts"]),
            "independent_human_reviews": 0, "network_eligible": False,
            "tokenizer_512_verified": False,
            "public_prompt_sha256": provenance["public_prompt_sha256"],
        }, indent=2))
        return 0
    except (ChallengeError, ReplayError, OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"FALSUM PRE-FIX CHALLENGE ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
