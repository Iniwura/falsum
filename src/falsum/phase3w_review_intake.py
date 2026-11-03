"""Phase 3W: low-friction GitHub Issue-form AppSec review claim intake.

A public GitHub author and syntactically correct review are NOT independent
professional accreditation, valid security labels, model improvements, or
eligible Telegraph evaluation rows. No exports or automatic training permitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import urllib.parse
import urllib.request

from .phase3f_multifamily_material import PINS
from .real_fix_corpus import load_queue

STATUS = "PHASE3W_GITHUB_REVIEW_CLAIMS_UNADJUDICATED_NO_LABELS"
PREFIX = "[FALSUM external review]"
HEADINGS = (
    "Public case", "Evidence-based preference",
    "Pinned source and regression-test lines", "Independent analysis",
    "Missing deployment facts", "Review attestation",
)
ATTESTATIONS = (
    "I personally inspected the primary public source and test evidence, and my analysis is not copied or AI-generated work presented as independent expert judgment.",
    "I understand my review is an unverified public contribution, not an accepted security label, evaluator registration, or confirmed Telegraph prize.",
    "I have not included private credentials, nonpublic security findings, or sensitive customer information.",
)
HEAD = re.compile(r"^### ([^\n]+)\s*$", re.M)
LINE = re.compile(r"^L([1-9]\d*)(?:-L([1-9]\d*))?$")
REVIEWER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37})$")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
TIMESTAMP = re.compile(r"^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
API_BASE = "https://api.github.com/repos/Iniwura/falsum/issues"
ROOT = Path(__file__).resolve().parents[2]


class ReviewClaimError(ValueError):
    """Refuse unsupported or misleading review intake claims."""


def reviewer_cases(root: Path = ROOT) -> dict[str, dict]:
    rows = []
    for filename in ("data/real-fix-queue.json", "data/real-fix-train-candidates.json"):
        payload = load_queue(root / filename)
        if len(payload["cases"]) != 4:
            raise ReviewClaimError("expected four exact source-fix cases per verified queue")
        rows.extend(payload["cases"])
    row_index = {item["id"]: item for item in rows}
    if len(rows) != 8 or len(row_index) != 8 or len(PINS) != 7:
        raise ReviewClaimError("the source-first review queue changed identities")
    output = {}
    for case_id, repo, commit, source_blob, test_blob in PINS:
        row = row_index.get(case_id)
        if (not row or row["repository"] != repo or row["commit"] != commit
                or row["source_blob"] != source_blob or row["test_blob"] != test_blob
                or not SHA40.fullmatch(row["parent"])):
            raise ReviewClaimError("upstream source, fix or regression-test identity drift")
        output[case_id] = row
    return output


def _fields(body: str) -> dict[str, str]:
    if not isinstance(body, str) or not 200 <= len(body) <= 25000:
        raise ReviewClaimError("issue form body length invalid")
    headers = list(HEAD.finditer(body))
    if len(headers) != len(HEADINGS) or tuple(h.group(1).strip() for h in headers) != HEADINGS:
        raise ReviewClaimError("missing/duplicated/reordered issue form fields")
    if body[:headers[0].start()].strip():
        raise ReviewClaimError("unexpected preamble before GitHub issue form")
    fields = {}
    for i, h in enumerate(headers):
        boundary = headers[i+1].start() if i+1 < len(headers) else len(body)
        fields[HEADINGS[i]] = body[h.end():boundary].strip()
    return fields


def _pinpoint(candidate: str, row: dict, path: str) -> bool:
    try:
        u = urllib.parse.urlsplit(candidate)
        expected_path = f'/{row["repository"]}/blob/{row["commit"]}/{path}'
        if (u.scheme != "https" or u.netloc != "github.com" or u.path != expected_path
                or u.query or u.username or u.password):
            return False
        line = LINE.fullmatch(u.fragment)
        if not line:
            return False
        lo, hi = int(line.group(1)), int(line.group(2) or line.group(1))
        return lo <= hi <= lo + 120 and hi <= 400000
    except (ValueError, TypeError):
        return False


def validate_issue(issue: dict, rows: dict[str, dict]) -> dict:
    if not isinstance(issue, dict) or not isinstance(issue.get("title"), str) or not issue["title"].startswith(PREFIX):
        raise ReviewClaimError("not a Phase 3W independent review issue")
    if issue.get("pull_request") is not None:
        raise ReviewClaimError("pull requests are not review submissions")
    user = issue.get("user")
    if not isinstance(user, dict) or user.get("type") != "User":
        raise ReviewClaimError("GitHub-authenticated human account metadata unavailable")
    login = user.get("login")
    if not isinstance(login, str) or not REVIEWER.fullmatch(login) or login.casefold() == "iniwura":
        raise ReviewClaimError("invalid reviewer, owner self-review or bot account")
    issue_id = issue.get("number")
    if type(issue_id) is not int or issue_id < 1:
        raise ReviewClaimError("invalid GitHub issue number")
    url = f"https://github.com/Iniwura/falsum/issues/{issue_id}"
    if issue.get("html_url") != url or issue.get("state") not in ("open", "closed"):
        raise ReviewClaimError("non-canonical GitHub issue identity or state")
    for key in ("created_at", "updated_at"):
        if not isinstance(issue.get(key), str) or not TIMESTAMP.fullmatch(issue[key]):
            raise ReviewClaimError("missing/unverifiable GitHub issue timestamp")
    if issue["updated_at"] < issue["created_at"]:
        raise ReviewClaimError("issue time moved backwards")
    fields = _fields(issue.get("body"))
    case_id, preference = fields[HEADINGS[0]], fields[HEADINGS[1]]
    if case_id not in rows:
        raise ReviewClaimError("source-fix case id is not pinned to seven-family queue")
    if preference not in ("A", "B", "ABSTAIN"):
        raise ReviewClaimError("unsupported preference; ABSTAIN is acceptable")
    if len(fields[HEADINGS[3]]) < 140 or len(fields[HEADINGS[4]]) < 75:
        raise ReviewClaimError("evidence-based reasoning or deployment limitations too brief")
    citations = fields[HEADINGS[2]]
    if len(citations) > 4500:
        raise ReviewClaimError("oversized citations field")
    row = rows[case_id]
    links = re.findall(r"https://[^\s<>()\[\]]+", citations)
    links = [u.rstrip(".,;") for u in links]
    if row["public_source"] not in links:
        raise ReviewClaimError("upstream primary advisory citation missing")
    if not any(_pinpoint(u, row, row["source_path"]) for u in links):
        raise ReviewClaimError("exact full-fix-SHA source file line citation missing")
    if not any(_pinpoint(u, row, row["test_path"]) for u in links):
        raise ReviewClaimError("exact full-fix-SHA regression test line citation missing")
    for text in ATTESTATIONS:
        if not re.search(r"(?mi)^- \[[xX]\] " + re.escape(text) + r"\s*$", fields[HEADINGS[5]]):
            raise ReviewClaimError("explicit human independence/safety attestation missing")
    return {
        "case_id": case_id, "preference_claim": preference,
        "issue_url": url, "issue_number": issue_id, "github_author": login,
        "created_at": issue["created_at"], "updated_at": issue["updated_at"],
        "submitted_body_sha256": hashlib.sha256(issue["body"].encode()).hexdigest(),
        "source_test_and_advisory_links_format_checked": True,
        "source_claim_correctness_verified": False,
        "independent_security_expertise_verified": False,
        "reviewer_authorship_independently_verified": False,
        "training_label_accepted": False,
    }


def assemble(issues: list[dict], rows: dict[str, dict], *, fetched_live: bool = False, pages: int = 0) -> dict:
    if not isinstance(issues, list):
        raise ReviewClaimError("GitHub issue snapshot must be a list")
    claims, rejected = [], []
    seen_authors = set()
    for issue in issues:
        if not isinstance(issue, dict) or not isinstance(issue.get("title"), str):
            continue
        if not issue["title"].startswith(PREFIX):
            continue
        try:
            claim = validate_issue(issue, rows)
        except (ReviewClaimError, KeyError, TypeError) as exc:
            rejected.append({"issue_number": issue.get("number"), "reason": str(exc)})
            continue
        unique = (claim["case_id"], claim["github_author"].casefold())
        if unique in seen_authors:
            rejected.append({"issue_number": claim["issue_number"],
                             "reason": "same GitHub account already claimed this case"})
            continue
        seen_authors.add(unique)
        claims.append(claim)
    coverage = []
    for case in rows:
        group = [c for c in claims if c["case_id"] == case]
        positions = sorted({c["preference_claim"] for c in group})
        coverage.append({
            "case_id": case, "format_valid_distinct_github_claims": len(group),
            "positions_claimed": positions,
            "unresolved_disagreement": len(positions) > 1,
            "independently_certified_security_labels": 0,
        })
    return {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "review_sources": len(rows), "github_issues_fetched_live": fetched_live,
        "fetched_complete_pages": pages if fetched_live else 0,
        "public_format_valid_claims": len(claims),
        "public_rejected_form_claims": len(rejected),
        "claims": claims, "rejected": rejected, "coverage": coverage,
        "independent_expert_certified_labels": 0, "trainable_preference_pairs": [],
        "accepted_training_pairs": 0, "new_eligible_anjoman_rows": 0,
        "registered_evaluator": False, "security_accuracy_certified": False,
        "network_eligible": False,
        "notice": "A form's GitHub author, signatures and citations establish attribution and format only. Authorship, expertise and underlying AppSec judgments need separate human verification. This does not promote review claims into training or network labels.",
    }


def fetch_live_issues(*, opener=None) -> tuple[list[dict], int]:
    """Read only the fixed public GitHub repository issue list, never arbitrary URLs."""
    open_url = opener or urllib.request.urlopen
    output = []
    token = os.environ.get("GITHUB_TOKEN")
    for n in range(1, 6):
        url = f"{API_BASE}?state=all&per_page=100&page={n}"
        headers = {"Accept": "application/vnd.github+json",
                   "User-Agent": "FALSUM-public-review-audit/1.0",
                   "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers)
        try:
            with open_url(request, timeout=20) as response:
                if response.geturl() != url:
                    raise ReviewClaimError("unsafe redirected GitHub API response")
                payload = response.read(2000001)
                if len(payload) > 2000000:
                    raise ReviewClaimError("oversized GitHub issues response")
            decoded = json.loads(payload)
        except (OSError, ValueError, TypeError) as exc:
            raise ReviewClaimError("unable to verify GitHub public issue list") from exc
        if not isinstance(decoded, list):
            raise ReviewClaimError("GitHub issues API did not return a list")
        output.extend(decoded)
        if len(decoded) < 100:
            return output, n
    raise ReviewClaimError("GitHub issue pagination exceeded bounded limit; do not claim exhaustive results")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit public GitHub reviewer claims, never certify labels")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--offline-issues", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.out.is_symlink():
            raise ReviewClaimError("refuse to overwrite an earlier review snapshot")
        rows = reviewer_cases()
        if args.offline_issues is None:
            issues, pages = fetch_live_issues()
            live = True
        else:
            issues, pages = json.loads(args.offline_issues.read_text(encoding="utf-8")), 0
            live = False
        report = assemble(issues, rows, fetched_live=live, pages=pages)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({
            "status": STATUS, "fetched_live": live,
            "format_valid_public_claims": report["public_format_valid_claims"],
            "independently_certified_labels": 0, "training_labels": 0,
        }, indent=2))
        return 0
    except (ReviewClaimError, OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"FALSUM PUBLIC REVIEW AUDIT ERROR: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
