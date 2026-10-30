"""Conservative intake of public GitHub AppSec review CLAIMS.

A submitted GitHub Issue is not proof of independent expertise, honest analysis,
evidence correctness, preference-label validity, or Anjoman eligibility.
This program NEVER exports training labels and NEVER promotes a reviewer claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

from .real_fix_corpus import load_queue

REPO_NAME = "Iniwura/falsum"
STATUS = "REVIEW_CLAIMS_REQUIRE_MANUAL_ADJUDICATION"
TITLE_PREFIX = "[AppSec review]"
HEADINGS = [
    "Public source case",
    "Is the claimed issue supported by this source fix and its regression test?",
    "Original security analysis",
    "Deployment preconditions and limitations",
    "Pinpoint source evidence",
    "Uncertainty, disagreement, and possible corrections",
    "Independent reviewer attestation",
]
DECISIONS = {
    "supported": "supported",
    "unsupported": "unsupported",
    "uncertain - needs more evidence": "uncertain",
}
ATTESTATIONS = (
    "I inspected the original primary evidence independently, and I am not submitting generated or copied analysis as a personal expert review.",
    "I understand this issue is a review proposal, not a verified acceptance, hackathon submission, or model training label.",
)
HEADER_PATTERN = re.compile(r"^### (.+?)\s*$", re.MULTILINE)
BLOB_LINE = re.compile(r"^L([1-9]\d*)(?:-L([1-9]\d*))?$")
LINK_PATTERN = re.compile(r"https://github\.com/[^\s<>()\[\]]+")
ALLOWED_REVIEWERS = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})\Z")


class IntakeError(ValueError):
    """Invalid issue evidence or untrustworthy API snapshot."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _valid_line_link(link: str, row: dict, ref: str, paths: set[str]) -> bool:
    url = urllib.parse.urlsplit(link)
    if (url.scheme != "https" or url.netloc != "github.com"
            or url.query or url.username or url.password):
        return False
    prefix = f'/{row["repository"]}/blob/{ref}/'
    if not url.path.startswith(prefix):
        return False
    target = urllib.parse.unquote(url.path[len(prefix):])
    if target not in paths:
        return False
    fragment = BLOB_LINE.fullmatch(url.fragment)
    if not fragment:
        return False
    a = int(fragment.group(1))
    b = int(fragment.group(2) or a)
    return a <= b and b - a <= 120 and b < 500000


def _fields(body: str) -> dict[str, str]:
    if not isinstance(body, str) or not 200 <= len(body) <= 30000:
        raise IntakeError("body missing or outside bounded review size")
    heads = list(HEADER_PATTERN.finditer(body))
    if len(heads) != len(HEADINGS) or [m.group(1).strip() for m in heads] != HEADINGS:
        raise IntakeError("issue form missing, reordered, or duplicated headings")
    # Reject non-form control text before first heading (except whitespace).
    if body[: heads[0].start()].strip():
        raise IntakeError("unexpected content before review form")
    fields = {}
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(body)
        fields[HEADINGS[i]] = body[head.end():end].strip()
    return fields


def validate_claim(issue: dict, queue_rows: dict[str, dict], *, owner: str = "Iniwura") -> dict:
    if not isinstance(issue, dict):
        raise IntakeError("issue snapshot not object")
    title = issue.get("title")
    if not isinstance(title, str) or not title.startswith(TITLE_PREFIX):
        raise IntakeError("not a structured independent review issue")
    if issue.get("pull_request"):
        raise IntakeError("pull request is not a reviewer issue")
    author = issue.get("user")
    if not isinstance(author, dict):
        raise IntakeError("missing GitHub-authenticated issue author")
    login = author.get("login")
    if (not isinstance(login, str) or not ALLOWED_REVIEWERS.fullmatch(login)
            or login.casefold() == owner.casefold()
            or author.get("type") != "User"):
        raise IntakeError("self-review, bot account, or invalid issue author")
    number = issue.get("number")
    if type(number) is not int or number < 1:
        raise IntakeError("missing issue number")
    canonical_url = f"https://github.com/{REPO_NAME}/issues/{number}"
    if issue.get("html_url") != canonical_url:
        raise IntakeError("GitHub issue canonical URL mismatch")
    state = issue.get("state")
    if state not in ("open", "closed"):
        raise IntakeError("invalid GitHub issue state")
    fields = _fields(issue.get("body"))
    case = fields[HEADINGS[0]]
    if case not in queue_rows:
        raise IntakeError("case id not in immutable source queue")
    row = queue_rows[case]
    verdict = DECISIONS.get(fields[HEADINGS[1]].lower())
    if verdict is None:
        raise IntakeError("verdict must be supported, unsupported, or uncertain")
    min_lengths = {
        HEADINGS[2]: 140, HEADINGS[3]: 100,
        HEADINGS[4]: 130, HEADINGS[5]: 75,
    }
    for field, minimum in min_lengths.items():
        content = fields[field]
        if len(content) < minimum or len(content) > 12000 or content in ("_No response_", "N/A"):
            raise IntakeError(f"insufficient substantive text: {field}")
    citations = fields[HEADINGS[4]]
    found = [link.rstrip(".,;") for link in LINK_PATTERN.findall(citations)]
    if row["public_source"] not in found:
        raise IntakeError("missing exact official GitHub advisory source")
    pre = any(_valid_line_link(link, row, row["parent"], {row["source_path"]}) for link in found)
    after = any(_valid_line_link(link, row, row["commit"],
                                 {row["source_path"], row["test_path"]}) for link in found)
    if not (pre and after):
        raise IntakeError("missing pinned parent code AND fix/test line citation")
    att = fields[HEADINGS[6]]
    for statement in ATTESTATIONS:
        if not re.search(r"(?mi)^- \[[xX]\] " + re.escape(statement) + r"\s*$", att):
            raise IntakeError("independent inspection and research-only attestations required")
    created = issue.get("created_at")
    updated = issue.get("updated_at")
    if (not isinstance(created, str) or not isinstance(updated, str)
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", created)
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", updated)
            or updated < created):
        raise IntakeError("cannot establish submitted date from GitHub metadata")
    return {
        "case_id": case, "issue_number": number, "issue_url": canonical_url,
        "github_author_login": login, "created_at": created, "updated_at": updated,
        "verdict_claim": verdict, "body_sha256": _digest(issue["body"]),
        "source_citations_format_checked": True,
        "source_claim_independently_verified": False,
        "technical_expertise_verified": False,
        "human_authorship_verified": False,
        "training_label_accepted": False,
        "assessment_status": "CLAIM_ONLY_AWAITING_MANUAL_SOURCE_AND_IDENTITY_ADJUDICATION",
    }


def assemble(queue: dict, issues: list[dict]) -> dict:
    if not isinstance(issues, list) or len(issues) > 1500:
        raise IntakeError("missing or unbounded GitHub issue snapshot")
    rows = queue.get("cases")
    if (queue.get("status") != "PUBLIC_PATCH_SOURCES_DRAFT_UNREVIEWED"
            or not isinstance(rows, list) or not rows):
        raise IntakeError("invalid research-only source queue")
    by_case = {row["id"]: row for row in rows}
    if len(by_case) != len(rows):
        raise IntakeError("duplicate source queue case")
    accepted_format = []
    rejected = []
    seen_numbers = set()
    for issue in issues:
        if not isinstance(issue, dict):
            raise IntakeError("non-object GitHub issue")
        number = issue.get("number")
        if type(number) is not int or number < 1 or number in seen_numbers:
            raise IntakeError("duplicate or invalid issue number in GitHub snapshot")
        seen_numbers.add(number)
        if issue.get("pull_request") or not isinstance(issue.get("title"), str) or not issue["title"].startswith(TITLE_PREFIX):
            continue
        try:
            accepted_format.append(validate_claim(issue, by_case))
        except IntakeError as exc:
            rejected.append({"issue_number": number, "issue_url": issue.get("html_url"),
                             "reason": str(exc)})
    grouped = []
    for row in rows:
        claims = [item for item in accepted_format if item["case_id"] == row["id"]]
        claims.sort(key=lambda x: (x["updated_at"], x["issue_number"]), reverse=True)
        unique = []
        used = set()
        for claim in claims:
            reviewer = claim["github_author_login"].casefold()
            if reviewer not in used:
                unique.append(claim)
                used.add(reviewer)
        unique.sort(key=lambda x: (x["github_author_login"].casefold(), x["issue_number"]))
        verdicts = {c["verdict_claim"] for c in unique}
        if not unique:
            status = "NO_VALID_REVIEW_CLAIMS"
        elif len(unique) == 1:
            status = "ONE_REVIEW_CLAIM_NEEDS_SECOND_INDEPENDENT_REVIEW"
        elif "uncertain" in verdicts:
            status = "UNCERTAINTY_REQUIRES_EXPERT_EVIDENCE"
        elif len(verdicts) > 1:
            status = "CONFLICTING_REVIEW_CLAIMS_NEED_ADJUDICATION"
        else:
            status = "MATCHING_CLAIMS_NOT_INDEPENDENTLY_VERIFIED"
        grouped.append({
            "case_id": row["id"], "repository": row["repository"],
            "status": status, "distinct_github_claim_authors": len(unique),
            "review_claims": unique,
            "human_validated_labels": 0,
            "network_eligible": False, "training_authorized": False,
        })
    return {
        "schema_version": 1, "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "source_case_count": len(rows), "issues_examined": len(issues),
        "structured_review_issues": len(rejected) + len(accepted_format),
        "valid_format_claims": len(accepted_format),
        "format_rejected": len(rejected), "format_rejections": rejected,
        "claims_from_distinct_authors": sum(c["distinct_github_claim_authors"] for c in grouped),
        "accepted_independent_expert_reviews": 0,
        "accepted_training_labels": 0,
        "exportable_preference_pairs": [],
        "network_eligible": False, "training_authorized": False,
        "model_accuracy_measured": False, "cases": grouped,
        "warning": "GitHub author/checkbox/citation format is NOT independent expertise, source correctness, human authorship, Anjoman eligibility, or a verified pairwise preference label.",
    }


def fetch_public_issues(repo: str = REPO_NAME) -> list[dict]:
    if repo != REPO_NAME:
        raise IntakeError("only exact FALSUM review repository is allowed")
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "FALSUM-independent-review-intake/1.0",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    collected = []
    for page in range(1, 17):
        url = f"https://api.github.com/repos/{repo}/issues?state=all&per_page=100&page={page}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=25) as response:
                redirected = urllib.parse.urlsplit(response.geturl())
                if redirected.scheme != "https" or redirected.netloc != "api.github.com" or redirected.path != f"/repos/{repo}/issues":
                    raise IntakeError("unexpected GitHub API redirect")
                payload = response.read(5_000_001)
            if len(payload) > 5_000_000:
                raise IntakeError("issue page exceeds safety bound")
            page_rows = json.loads(payload)
        except (OSError, ValueError) as exc:
            raise IntakeError(f"GitHub issue listing failed on page {page}: {exc}") from exc
        if not isinstance(page_rows, list) or len(page_rows) > 100:
            raise IntakeError("unexpected GitHub issue listing payload")
        collected.extend(page_rows)
        if len(page_rows) < 100:
            return collected
    raise IntakeError("pagination cap reached; refuse incomplete review inventory")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect public GitHub review claims without accepting training labels")
    parser.add_argument("--queue", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--issues-json", type=Path, help="Offline synthetic test input; do not use to claim real reviews")
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.out.resolve() == args.queue.resolve() or (
                args.issues_json and args.out.resolve() == args.issues_json.resolve()):
            raise IntakeError("refusing to overwrite existing source, issue snapshot, or report")
        queue = load_queue(args.queue)
        issues = (json.loads(args.issues_json.read_text(encoding="utf-8"))
                  if args.issues_json else fetch_public_issues())
        result = assemble(queue, issues)
        result["input_source"] = "OFFLINE_UNTRUSTED_FIXTURE" if args.issues_json else "PUBLIC_GITHUB_API"
        result["source_queue_sha256"] = hashlib.sha256(args.queue.read_bytes()).hexdigest()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({k: result[k] for k in (
            "status", "input_source", "source_case_count", "issues_examined",
            "valid_format_claims", "format_rejected", "accepted_independent_expert_reviews",
            "accepted_training_labels", "network_eligible")}, indent=2))
        return 0
    except (IntakeError, OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"FALSUM REVIEW INTAKE ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
