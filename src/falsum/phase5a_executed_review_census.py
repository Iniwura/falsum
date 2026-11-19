"""Live read-only GitHub census for the FOUR executed-source review form.

The legacy independent_review_intake.py handles a DIFFERENT four-case research
queue. This module accepts only the Phase 4X Koa/Hono/LangChain issue form.
It checks public issue formatting and exact immutable source/test references.
It NEVER verifies reviewer qualifications, human authorship, semantics, model
accuracy, new Anjoman rows, gold labels, or main hackathon acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from .independent_review_intake import fetch_public_issues
from .source_review_witness_gate import validated_index

STATUS = "PHASE5A_FOUR_EXECUTED_SOURCE_REVIEW_CLAIMS_UNADJUDICATED"
PREFIX = "[FALSUM independent executed-source review]"
HEADINGS = (
    "Exact historical upstream repair stage",
    "Independent source assessment",
    "Immutable parent and fixed code references",
    "Actual upstream regression test and observed evidence",
    "Reviewer's original security analysis",
    "Missing deployment and attacker preconditions",
    "Weaknesses, counterexamples or disagreements",
    "Relevant experience, conflicts and AI assistance",
    "Review integrity",
)
CHOICES = (
    "SOURCE_CHANGE_SUPPORTED_WITH_LIMITS",
    "SOURCE_CHANGE_INCOMPLETE_OR_CONTRADICTED",
    "ABSTAIN_NEEDS_MORE_PRIMARY_EVIDENCE",
)
DECLARATIONS = (
    "I inspected original public upstream code/test myself and disclosed assistance or conflicts rather than asserting unearned independent expert status.",
    "I understand this issue is a public source claim requiring separate adjudication, not an accepted gold label, training approval, formal H2 entry or paid endorsement.",
    "My submission excludes secrets, private evaluation prompts, customer data and restricted unpublished security details.",
)
HEAD = re.compile(r"^### ([^\n]+)[ \t]*$", re.MULTILINE)
LINK = re.compile(r"https://github\.com/[^\s<>\[\]()]+")
LINES = re.compile(r"^L([1-9][0-9]*)(?:-L([1-9][0-9]*))?$")
LOGIN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37})$")
STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
MAX_ISSUES = 2000

class CensusError(ValueError):
    pass

def need(ok: bool, reason: str) -> None:
    if not ok:
        raise CensusError(reason)

def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def fields(body: str) -> dict[str, str]:
    need(isinstance(body, str) and 200 <= len(body) <= 30000,
         "missing or oversized review form body")
    matches = list(HEAD.finditer(body))
    need(len(matches) == len(HEADINGS) and
         [m.group(1).strip() for m in matches] == list(HEADINGS) and
         not body[:matches[0].start()].strip(),
         "missing, duplicated, or reordered official review headings")
    output = {}
    for i, heading in enumerate(HEADINGS):
        end = matches[i+1].start() if i+1 < len(matches) else len(body)
        output[heading] = body[matches[i].end():end].strip()
    return output

def source_link_valid(raw: str, witness: dict, revision: str, kind: str, stage: dict) -> bool:
    """Validate exact Git SHA, unescaped file path and bounded line permalink."""
    uri = urlsplit(raw.rstrip(".,;"))
    if uri.scheme != "https" or uri.netloc != "github.com" or uri.query or uri.username or uri.password:
        return False
    commit = witness["original_git_commit"] if revision == "parent" else witness["fixed_git_commit"]
    path = stage["source_path"] if kind == "source" else stage["test_path"]
    if uri.path != f"/{witness['repository']}/blob/{commit}/{path}":
        return False
    m = LINES.fullmatch(uri.fragment)
    if not m:
        return False
    a, b = int(m.group(1)), int(m.group(2) or m.group(1))
    return a <= b and (b - a) <= 120 and b <= 500000

def case_stages(index: dict, lock: dict) -> dict:
    require = {}
    for case_id, w in index.items():
        matches = [
            s for row in lock["cases"] if row["repository"] == w["repository"]
            for s in row["patches"] if s["stage"] == w["stage"]
        ]
        need(len(matches) == 1, "review case source stage cannot be resolved")
        require[case_id] = matches[0]
    need(tuple(require) == ("koa-redirect", "hono-csrf", "langchain-path", "langchain-symlink"),
         "noncanonical four-case executed witness order")
    return require

def inspect_issue(issue: dict, index: dict, stages: dict) -> dict:
    need(isinstance(issue, dict) and
         isinstance(issue.get("title"), str) and issue["title"].startswith(PREFIX) and
         not issue.get("pull_request"), "not a four-witness review issue")
    author = issue.get("user")
    login = author.get("login") if isinstance(author, dict) else None
    need(isinstance(login, str) and LOGIN.fullmatch(login) is not None and
         login.casefold() != "iniwura" and author.get("type") == "User",
         "reviewer is owner, bot or lacks GitHub authenticated account type")
    num = issue.get("number")
    need(type(num) is int and num >= 1 and
         issue.get("html_url") == f"https://github.com/Iniwura/falsum/issues/{num}" and
         issue.get("state") in ("open", "closed"),
         "invalid GitHub issue identity or state")
    created, updated = issue.get("created_at"), issue.get("updated_at")
    need(isinstance(created, str) and STAMP.fullmatch(created) is not None and
         isinstance(updated, str) and STAMP.fullmatch(updated) is not None and
         updated >= created, "invalid GitHub issue timestamp provenance")

    body = issue.get("body")
    f = fields(body)
    ident = f[HEADINGS[0]]
    need(ident in index and ident in stages, "reviewed case is not an executed source stage")
    verdict = f[HEADINGS[1]]
    need(verdict in CHOICES, "review omitted independent source verdict or ABSTAIN")
    for heading, minimum in (
        (HEADINGS[2], 80), (HEADINGS[3], 75), (HEADINGS[4], 120),
        (HEADINGS[5], 90), (HEADINGS[6], 50), (HEADINGS[7], 50)
    ):
        value = f[heading]
        need(minimum <= len(value) <= 12000 and value not in ("_No response_", "N/A"),
             "empty or insufficient source-first disclosure: " + heading)

    w, stage = index[ident], stages[ident]
    parent_links = [u for u in LINK.findall(f[HEADINGS[2]]) if source_link_valid(u,w,"parent","source",stage)]
    fixed_links = [u for u in LINK.findall(f[HEADINGS[2]]) if source_link_valid(u,w,"fixed","source",stage)]
    test_links = [u for u in LINK.findall(f[HEADINGS[3]]) if source_link_valid(u,w,"fixed","test",stage)]
    need(bool(parent_links) and bool(fixed_links) and bool(test_links),
         "source/test citation lacks exact pinned commits, paths or line numbers")
    declaration = f[HEADINGS[8]]
    for attestation in DECLARATIONS:
        need(re.search(r"(?m)^- \[[xX]\] " + re.escape(attestation) + r"\s*$",
                       declaration) is not None,
             "incomplete review integrity attestation")

    return {
        "case_id": ident, "issue_number": num,
        "issue_url": issue["html_url"], "github_login": login,
        "github_issue_created_at": created, "github_issue_updated_at": updated,
        "stated_verdict": verdict, "body_sha256": digest(body),
        "source_parent_and_fixed_line_urls_format_checked": True,
        "upstream_regression_test_line_url_format_checked": True,
        "public_github_account_authorship_only": True,
        "original_analysis_and_conflicts_self_reported": True,
        "reviewer_is_independent_human_verified": False,
        "appsec_expertise_independently_verified": False,
        "claim_source_semantics_independently_verified": False,
        "expert_gold_label_approved": False,
        "eligible_for_training": False,
    }

def assemble(index_raw: bytes, lock_raw: bytes, issues: list[dict], *, live: bool) -> dict:
    index = validated_index(index_raw, lock_raw)
    from .phase4p_open_source_review import load_lock
    stage = case_stages(index, load_lock(lock_raw))
    need(type(live) is bool and isinstance(issues, list) and len(issues) <= MAX_ISSUES,
         "invalid GitHub issue census inputs")
    seen = set()
    formatted, rejected = [], []
    for issue in issues:
        need(isinstance(issue, dict) and type(issue.get("number")) is int and
             issue["number"] > 0 and issue["number"] not in seen,
             "duplicate/malformed GitHub issue identity; refuse incomplete census")
        seen.add(issue["number"])
        if issue.get("pull_request") or not isinstance(issue.get("title"), str) or not issue["title"].startswith(PREFIX):
            continue
        try:
            formatted.append(inspect_issue(issue, index, stage))
        except CensusError as exc:
            rejected.append({
                "issue_number": issue["number"], "issue_url": issue.get("html_url"),
                "format_reason": str(exc),
            })
    per_case = []
    for case_id, w in index.items():
        all_claims = sorted(
            (x for x in formatted if x["case_id"] == case_id),
            key=lambda q: (q["github_issue_updated_at"], q["issue_number"]), reverse=True
        )
        unique = []
        seen_authors = set()
        for claim in all_claims:
            author_key = claim["github_login"].casefold()
            if author_key not in seen_authors:
                seen_authors.add(author_key)
                unique.append(claim)
        labels = sorted({x["stated_verdict"] for x in unique})
        status = ("NO_FORMAT_VALID_EXTERNAL_REVIEW_CLAIMS" if not unique else
                  "UNADJUDICATED_ABSTENTION_OR_DISAGREEMENT" if
                  len(labels) > 1 or CHOICES[2] in labels else
                  "UNADJUDICATED_AGREEMENT_IS_NOT_GOLD" if len(unique) > 1 else
                  "ONE_UNADJUDICATED_EXTERNAL_ACCOUNT_CLAIM")
        per_case.append({
            "case_id": case_id, "repository": w["repository"],
            "original_upstream_execution_sha256": w["raw_source_runtime_receipt_sha256"],
            "format_valid_distinct_github_accounts": len(unique),
            "claimed_verdicts": labels, "status": status,
            "reviews_needing_independent_adjudication": unique,
            "verified_independent_human_expert_labels": 0,
        })
    return {
        "schema_version": 1, "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "input_source": "PUBLIC_GITHUB_API" if live else "OFFLINE_UNTRUSTED_FIXTURE",
        "source_lock_sha256": hashlib.sha256(lock_raw).hexdigest(),
        "authenticated_four_stage_index_sha256": hashlib.sha256(index_raw).hexdigest(),
        "source_executed_upstream_stages": len(index),
        "source_executed_distinct_projects": len({x["repository"] for x in index.values()}),
        "github_issues_examined": len(issues),
        "review_form_issues": len(formatted) + len(rejected),
        "format_valid_review_claims": len(formatted),
        "format_rejected_review_claims": len(rejected),
        "format_rejections": rejected,
        "distinct_accounts_in_per_case_claims": sum(x["format_valid_distinct_github_accounts"] for x in per_case),
        "verified_independent_human_expert_labels": 0,
        "source_semantic_review_accuracy": None,
        "new_blind_holdout_accuracy": None,
        "training_eligible_rows": [],
        "new_anjoman_evaluation_rows": 0,
        "registered_evaluator": False,
        "official_h2_submission_confirmed": False,
        "cases": per_case,
        "warning": (
            "GitHub issue identity, exact source SHA permalink and checkbox formatting "
            "do not prove independent human authorship, security expertise, semantic "
            "source correctness, expert gold, model quality or Telegraph acceptance. "
            "External assessments remain unadjudicated even if multiple accounts agree."
        ),
    }

def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only independent review census for four authenticated upstream fixes")
    p.add_argument("--index", required=True, type=Path)
    p.add_argument("--source-lock", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--issues-json", type=Path, help="offline synthetic data; never imply GitHub API provenance")
    a = p.parse_args(argv)
    try:
        inputs = {a.index.resolve(), a.source_lock.resolve()}
        if a.issues_json is not None:
            inputs.add(a.issues_json.resolve())
        need(not a.out.exists() and not a.out.is_symlink() and a.out.resolve() not in inputs,
             "output must be a new path and not overwrite previous evidence")
        index_raw = a.index.read_bytes()
        lock_raw = a.source_lock.read_bytes()
        issues = (fetch_public_issues() if a.issues_json is None
                  else json.loads(a.issues_json.read_text(encoding="utf-8")))
        result = assemble(index_raw, lock_raw, issues, live=a.issues_json is None)
        a.out.parent.mkdir(parents=True, exist_ok=True)
        fd = a.out.open("x", encoding="utf-8")
        with fd:
            json.dump(result, fd, indent=2, sort_keys=True)
            fd.write("\n")
        print(json.dumps({
            "status": STATUS, "source": result["input_source"],
            "valid_claims": result["format_valid_review_claims"],
            "rejected_claims": result["format_rejected_review_claims"],
            "verified_human_expert_gold": 0, "model_accuracy": None,
        }, sort_keys=True))
        return 0
    except (CensusError, OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        p.exit(1, "FALSUM PHASE5A REVIEW INTAKE BLOCKED: " + str(exc)[:250] + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
