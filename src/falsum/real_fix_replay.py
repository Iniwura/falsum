"""Reconstruct the actual public upstream pre/post security-fix file revisions.

This prevents a merely plausible API patch fragment from being mistaken for a
verified before/after code transition. No exploit or human label is inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

MAX_FILE_BYTES = 1_500_000
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:.*)$")
REF = re.compile(r"[0-9a-f]{40}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
PATH = re.compile(r"[A-Za-z0-9_./-]+\Z")


class ReplayError(ValueError):
    """Missing upstream bytes, changed source, or inapplicable patch."""


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def raw_url(repo: str, ref: str, path: str) -> str:
    if (not isinstance(repo, str) or not REPO.fullmatch(repo)
            or not isinstance(ref, str) or not REF.fullmatch(ref)
            or not isinstance(path, str) or not PATH.fullmatch(path)
            or path.startswith("/") or any(x in ("", ".", "..") for x in path.split("/"))):
        raise ReplayError("untrusted source repository/ref/path")
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def fetch_raw(url: str) -> bytes:
    p = urllib.parse.urlsplit(url)
    if p.scheme != "https" or p.netloc != "raw.githubusercontent.com" or not re.fullmatch(
            r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[0-9a-f]{40}/[A-Za-z0-9_./-]+", p.path):
        raise ReplayError("untrusted raw source location")
    req = urllib.request.Request(url, headers={"User-Agent": "FALSUM-source-replay/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            end = urllib.parse.urlsplit(resp.geturl())
            if end.scheme != "https" or end.netloc != p.netloc or end.path != p.path:
                raise ReplayError("unexpected source redirect")
            content = resp.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ReplayError(f"cannot fetch pinned source: {exc}") from exc
    if len(content) > MAX_FILE_BYTES or b"\0" in content:
        raise ReplayError("source exceeds safety bound or is binary")
    return content


def apply_patch(old: bytes, patch: str) -> bytes:
    """Apply GitHub's single-file unified hunks, exact line content, no fuzz."""
    if not isinstance(patch, str):
        raise ReplayError("source patch is missing")
    try:
        text = old.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayError("source must be UTF-8 for replay") from exc
    if text and not text.endswith("\n"):
        raise ReplayError("non-newline source requires explicit EOF handling")
    original = text.splitlines()
    output = []
    cursor = 0
    lines = patch.splitlines()
    hunk_count = 0
    idx = 0
    while idx < len(lines):
        header = HUNK.fullmatch(lines[idx])
        if not header:
            raise ReplayError("unsupported or missing diff hunk header")
        start, n_old, target, n_new = header.groups()
        old_start = int(start) - 1 if int(start) > 0 else 0
        new_start = int(target) - 1 if int(target) > 0 else 0
        n_old = int(n_old) if n_old is not None else 1
        n_new = int(n_new) if n_new is not None else 1
        if old_start < cursor or old_start > len(original):
            raise ReplayError("overlapping or out-of-range hunk")
        output.extend(original[cursor:old_start])
        if len(output) != new_start:
            raise ReplayError("unified hunk line locations contradict previous hunks")
        cursor = old_start
        got_old = got_new = 0
        idx += 1
        while idx < len(lines) and not HUNK.fullmatch(lines[idx]):
            line = lines[idx]
            if line == r"\ No newline at end of file":
                raise ReplayError("unsupported no-newline hunk")
            if not line or line[0] not in (" ", "+", "-"):
                raise ReplayError("invalid unified patch line")
            symbol, payload = line[0], line[1:]
            if symbol in (" ", "-"):
                if cursor >= len(original) or original[cursor] != payload:
                    raise ReplayError("diff context or removed line does not match parent")
                cursor += 1
                got_old += 1
            if symbol in (" ", "+"):
                output.append(payload)
                got_new += 1
            idx += 1
        if got_old != n_old or got_new != n_new:
            raise ReplayError("unified hunk line counts are inconsistent")
        hunk_count += 1
    if hunk_count == 0:
        raise ReplayError("no replayable hunks")
    output.extend(original[cursor:])
    return ("\n".join(output) + "\n").encode("utf-8") if output else b""


def replay_case(row: dict, reader: Callable[[str], bytes] = fetch_raw) -> dict:
    if not isinstance(row, dict) or row.get("external_review_status") != "NOT_REVIEWED":
        raise ReplayError("real-fix case missing unreviewed provenance")
    if row.get("network_eligible") is not False or row.get("training_authorized") is not False:
        raise ReplayError("source row was incorrectly promoted")
    result = {"case_id": row["id"], "repository": row["repository"],
              "commit": row["commit"], "parent": row["parent"], "files": {},
              "independent_human_reviews": 0, "network_eligible": False}
    for key in ("source", "regression_test"):
        entry = row[key]
        path = entry["file_path"]
        before = reader(raw_url(row["repository"], row["parent"], path))
        after = reader(raw_url(row["repository"], row["commit"], path))
        expected = entry["post_fix_blob"]
        if git_blob_sha(after) != expected:
            raise ReplayError(f"{row['id']}/{key}: Git blob SHA mismatches pinned upstream post-fix file")
        if hashlib.sha256(entry["patch"].encode("utf-8")).hexdigest() != entry["sha256"]:
            raise ReplayError(f"{row['id']}/{key}: public API patch changed after manifest creation")
        reconstructed = apply_patch(before, entry["patch"])
        if reconstructed != after:
            raise ReplayError(f"{row['id']}/{key}: patch replay does not reconstruct true upstream bytes")
        result["files"][key] = {
            "path": path, "parent_git_blob": git_blob_sha(before),
            "post_fix_git_blob": expected,
            "parent_sha256": hashlib.sha256(before).hexdigest(),
            "post_fix_sha256": hashlib.sha256(after).hexdigest(),
            "exact_patch_replay_verified": True,
        }
    return result


def verify_report(report: dict, reader: Callable[[str], bytes] = fetch_raw) -> dict:
    if (not isinstance(report, dict) or report.get("status") != "SOURCE_VERIFIED_LABELS_UNREVIEWED"
            or report.get("independent_human_reviews") != 0
            or report.get("training_authorized") is not False
            or report.get("network_eligible") is not False):
        raise ReplayError("real-source report must remain unreviewed and unsubmitted")
    cases = report.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ReplayError("missing source cases")
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if hashlib.sha256(canonical.encode("utf-8")).hexdigest() != report.get("cases_sha256"):
        raise ReplayError("case manifest digest disagrees with source evidence bytes")
    verified = [replay_case(row, reader) for row in cases]
    return {
        "schema_version": 1,
        "status": "REAL_PATCH_REPLAY_VERIFIED_NO_LABELS",
        "cases_replayed": len(verified),
        "file_replays_verified": sum(len(row["files"]) for row in verified),
        "independent_human_reviews": 0, "network_eligible": False,
        "training_authorized": False, "source_cases_sha256": report["cases_sha256"],
        "verified": verified,
        "warning": "Historical public fix bytes replayed. This does NOT establish exploitability, expert review, or permission to train/register.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay upstream commits exactly; never infer security labels")
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise ReplayError("refusing to overwrite existing replay report")
        report = json.loads(args.evidence.read_text(encoding="utf-8"))
        result = verify_report(report)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({k: result[k] for k in ("status", "cases_replayed", "file_replays_verified",
                                                "independent_human_reviews", "network_eligible")}, indent=2))
        return 0
    except (ReplayError, OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"FALSUM REAL-FIX REPLAY ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
