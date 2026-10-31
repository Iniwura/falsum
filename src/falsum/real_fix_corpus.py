"""Source-pinned public security-fix corpus, never an independent evaluation label.

Three real disclosed repairs are fetched from immutable GitHub commits. Pinned
parent SHA and source/test blob object IDs detect wrong revisions or paths.
The result is a reviewer-facing evidence packet, NOT a training dataset.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

SCHEMA = 1
STATUS = "PUBLIC_PATCH_SOURCES_DRAFT_UNREVIEWED"
HEX40 = re.compile(r"[a-f0-9]{40}\Z")
GHSA = re.compile(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\Z", re.I)
CVE = re.compile(r"CVE-20[0-9]{2}-[0-9]{4,}\Z")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
PATH = re.compile(r"[A-Za-z0-9_./-]+\Z")
ID = re.compile(r"real-[a-z0-9-]+\Z")
CASE_FIELDS = {
    "id", "repository", "commit", "parent", "source_path", "source_blob",
    "test_path", "test_blob", "advisory", "cve", "family",
    "hypothesis_to_review", "public_source",
}
MAX_JSON_BYTES = 2_000_000
MAX_PATCH_BYTES = 15_000


class RealFixError(ValueError):
    """Public source or provenance verification failed."""


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_path(value: object) -> bool:
    return (isinstance(value, str) and bool(PATH.fullmatch(value))
            and not value.startswith("/") and
            all(part not in ("", ".", "..") for part in value.split("/")))


def load_queue(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RealFixError(f"cannot load queue: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "status", "intent", "cases"}:
        raise RealFixError("queue schema contains unknown or missing fields")
    if raw["schema_version"] != SCHEMA or raw["status"] != STATUS or raw["intent"] != "SECURITY_REVIEW_GENERAL":
        raise RealFixError("research-only queue status or intent invalid")
    items = raw["cases"]
    if not isinstance(items, list) or len(items) < 3 or len(items) > 20:
        raise RealFixError("expected 3..20 carefully selected public fixes")
    ids, commits, projects, families = set(), set(), set(), set()
    for row in items:
        if not isinstance(row, dict) or set(row) != CASE_FIELDS:
            raise RealFixError("real-fix case schema mismatch")
        for field in ("id", "repository", "advisory", "cve", "family",
                      "public_source", "hypothesis_to_review"):
            if not isinstance(row[field], str) or not row[field].strip():
                raise RealFixError(f"invalid field {field}")
        if not ID.fullmatch(row["id"]) or not REPO.fullmatch(row["repository"]):
            raise RealFixError("case or repository name invalid")
        if not GHSA.fullmatch(row["advisory"]) or not CVE.fullmatch(row["cve"]):
            raise RealFixError("GHSA/CVE format invalid")
        if not all(isinstance(row[k], str) and HEX40.fullmatch(row[k])
                   for k in ("commit", "parent", "source_blob", "test_blob")):
            raise RealFixError("missing immutable commit/parent/blob identity")
        if row["commit"] == row["parent"] or row["source_blob"] == row["test_blob"]:
            raise RealFixError("commit or file object identities incorrectly reused")
        if not _is_path(row["source_path"]) or not _is_path(row["test_path"]) or row["source_path"] == row["test_path"]:
            raise RealFixError("invalid or repeated source/test path")
        url = f'https://github.com/{row["repository"]}/security/advisories/{row["advisory"]}'
        central_url = f'https://github.com/advisories/{row["advisory"]}'
        if row["public_source"] not in (url, central_url):
            raise RealFixError("advisory URL must match exact repository or GitHub Advisory Database GHSA")
        # A GitHub Advisory Database link is not a maintainer-issued repository
        # advisory. Source authenticity still comes from immutable Git commits,
        # not from attributing a central listing to the upstream maintainers.
        if len(row["hypothesis_to_review"]) > 700 or len(row["hypothesis_to_review"]) < 90:
            raise RealFixError("review hypothesis must be bounded and substantive")
        if row["id"] in ids or row["commit"] in commits or row["repository"] in projects or row["family"] in families:
            raise RealFixError("case/commit/project/family duplicated; no project-level holdout leakage")
        ids.add(row["id"])
        commits.add(row["commit"])
        projects.add(row["repository"])
        families.add(row["family"])
    return raw


def fetch_github_commit(url: str) -> dict:
    # Only API paths constructed from validated slugs and full SHA, never user URLs.
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com" or not re.fullmatch(
            r"/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/commits/[a-f0-9]{40}", parsed.path):
        raise RealFixError("untrusted commit API destination")
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "FALSUM-source-audit/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            final = urllib.parse.urlsplit(resp.geturl())
            if final.scheme != "https" or final.netloc != "api.github.com" or final.path != parsed.path:
                raise RealFixError("redirected outside pinned GitHub API path")
            payload = resp.read(MAX_JSON_BYTES + 1)
            if len(payload) > MAX_JSON_BYTES:
                raise RealFixError("commit API response larger than safety bound")
        data = json.loads(payload)
    except (OSError, ValueError, urllib.error.HTTPError) as exc:
        raise RealFixError(f"GitHub commit API failed: {exc}") from exc
    if not isinstance(data, dict):
        raise RealFixError("commit API did not return object")
    return data


def _selected_patch(file: dict, name: str, blob: str, key: str, *, require_removed: bool = False) -> dict:
    if not isinstance(file, dict) or file.get("filename") != name or file.get("sha") != blob:
        raise RealFixError(f"{key}: wrong upstream source path/blob")
    if file.get("status") != "modified":
        raise RealFixError(f"{key}: patch must modify an existing file")
    patch = file.get("patch")
    if not isinstance(patch, str) or not patch.startswith("@@ ") or len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise RealFixError(f"{key}: missing or oversized textual patch")
    if require_removed and not any(line.startswith("-") and not line.startswith("---") for line in patch.splitlines()):
        raise RealFixError(f"{key}: patch lacks removed source lines")
    if not any(line.startswith("+") and not line.startswith("+++") for line in patch.splitlines()):
        raise RealFixError(f"{key}: patch lacks added source lines")
    return {"file_path": name, "post_fix_blob": blob,
            "sha256": digest(patch), "patch": patch}


def verify_commit(row: dict, source: dict) -> dict:
    if not isinstance(source, dict) or source.get("sha") != row["commit"]:
        raise RealFixError(f"{row['id']}: wrong upstream commit SHA")
    parents = source.get("parents")
    if (not isinstance(parents, list) or len(parents) != 1
            or not isinstance(parents[0], dict) or parents[0].get("sha") != row["parent"]):
        raise RealFixError(f"{row['id']}: commit parent mismatch (must be single-parent patch)")
    if source.get("html_url") != f'https://github.com/{row["repository"]}/commit/{row["commit"]}':
        raise RealFixError(f"{row['id']}: unexpected canonical commit URL")
    files = source.get("files")
    if not isinstance(files, list) or not files or len(files) > 100:
        raise RealFixError(f"{row['id']}: missing or oversized change list")
    matches = {f.get("filename"): f for f in files if isinstance(f, dict)}
    main = _selected_patch(matches.get(row["source_path"]), row["source_path"], row["source_blob"], row["id"], require_removed=True)
    test = _selected_patch(matches.get(row["test_path"]), row["test_path"], row["test_blob"], row["id"])
    if main["sha256"] == test["sha256"]:
        raise RealFixError(f"{row['id']}: source and test patch are identical")
    return {"id": row["id"], "intent": "SECURITY_REVIEW_GENERAL",
            "repository": row["repository"], "family": row["family"],
            "advisory": row["advisory"], "cve": row["cve"],
            "commit": row["commit"], "parent": row["parent"],
            "commit_url": source["html_url"], "advisory_url": row["public_source"],
            "source": main, "regression_test": test,
            "stated_applicability_to_verify": row["hypothesis_to_review"],
            "external_review_status": "NOT_REVIEWED",
            "proposed_preference_label": None,
            "training_authorized": False, "network_eligible": False}


def assemble(queue: dict, fetcher: Callable[[str], dict] | None = None) -> dict:
    if fetcher is None:
        fetcher = fetch_github_commit
    if not isinstance(queue, dict) or queue.get("status") != STATUS:
        raise RealFixError("queue not marked draft-only")
    cases = []
    for row in queue["cases"]:
        url = f'https://api.github.com/repos/{row["repository"]}/commits/{row["commit"]}'
        cases.append(verify_commit(row, fetcher(url)))
    canonical = json.dumps(cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {"schema_version": 1, "status": "SOURCE_VERIFIED_LABELS_UNREVIEWED",
            "intent": "SECURITY_REVIEW_GENERAL",
            "source_verified": len(cases), "independent_human_reviews": 0,
            "network_eligible": False, "training_authorized": False,
            "not_usable_as_accuracy_benchmark": True,
            "cases_sha256": digest(canonical), "cases": cases,
            "warning": "Actual upstream public fix commits; human accuracy labels and deployment exploitability NOT independently established."}


def reviewer_packet(report: dict) -> dict:
    if report.get("status") != "SOURCE_VERIFIED_LABELS_UNREVIEWED" or report.get("independent_human_reviews") != 0:
        raise RealFixError("review packet must originate from unreviewed verified sources")
    rows = []
    for item in report["cases"]:
        rows.append({
            "case_id": item["id"], "repository": item["repository"],
            "fix_commit_url": item["commit_url"], "security_advisory_url": item["advisory_url"],
            "pre_fix_commit_sha": item["parent"], "post_fix_commit_sha": item["commit"],
            "review_hypothesis": item["stated_applicability_to_verify"],
            "source_file": item["source"]["file_path"], "source_patch": item["source"]["patch"],
            "regression_test_file": item["regression_test"]["file_path"],
            "regression_test_patch": item["regression_test"]["patch"],
            "review_questions": [
                "What security boundary did the pre-fix code fail to enforce? Cite exact code and advisory evidence.",
                "Under what deployment conditions would a caller be affected? Identify conditions NOT shown by this patch.",
                "Does the repair and its regression test support the stated security conclusion? Note gaps and uncertainties.",
                "Record independently verified file/commit citations, reviewer GitHub identity and date; do not use the proposed draft status as a label.",
            ],
            "allowed_assessment": ["supported", "unsupported", "uncertain"],
            "review_status": "UNREVIEWED",
        })
    return {"schema_version": 1, "status": "HUMAN_REVIEW_REQUIRED_NOT_A_TRAINING_SET",
            "proposed_labels": 0, "human_reviews": 0, "network_eligible": False,
            "source_cases_sha256": report["cases_sha256"], "questions": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit immutable public security patches; no evaluation labels")
    parser.add_argument("--queue", type=Path, default=Path("data/real-fix-queue.json"))
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--reviewer-out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.resolve() == args.reviewer_out.resolve() or args.out.exists() or args.reviewer_out.exists():
            raise RealFixError("output destinations must be distinct and nonexistent")
        queue = load_queue(args.queue)
        report = assemble(queue)
        questions = reviewer_packet(report)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.reviewer_out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        args.reviewer_out.write_text(json.dumps(questions, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        print(json.dumps({"status": report["status"], "source_verified": report["source_verified"],
                          "independent_human_reviews": 0, "network_eligible": False,
                          "cases_sha256": report["cases_sha256"]}, indent=2))
        return 0
    except (RealFixError, OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"FALSUM REAL-FIX AUDIT ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
