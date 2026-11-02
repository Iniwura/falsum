"""Phase 3G: attribute public GitHub review comments without laundering labels.

Retrieves FALSUM issue #3 comments directly from GitHub and binds each
structured review to seven Phase 3F source-and-test-pinned questions.
GitHub authorship is not independent AppSec expertise or a security label.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import urllib.request
from pathlib import Path

from .phase3f_multifamily_material import PINS, STATUS as PACKET_STATUS

STATUS = "PHASE3G_GITHUB_ATTRIBUTED_REVIEW_CLAIMS_NOT_EXPERT_LABELS"
ISSUE_API = "https://api.github.com/repos/Iniwura/falsum/issues/3"
ISSUE_WEB = "https://github.com/Iniwura/falsum/issues/3"
TAG = re.compile(r"```falsum-review-v1\s*\n(.*?)\n```", re.DOTALL)
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SUBMISSION_KEYS = {
    "schema_version", "packet_bundle_sha256", "packet_id", "candidate_answer_sha256",
    "preference", "source_url", "test_url", "reasoning", "unresolved_facts",
}


class ReviewError(ValueError):
    """Public review source, authorship or packet binding is invalid."""


def canonical(obj: object) -> bytes:
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha(obj: object) -> str:
    return hashlib.sha256(canonical(obj)).hexdigest()


def check_bundle(bundle: dict) -> dict[str, dict]:
    if (not isinstance(bundle, dict) or bundle.get("schema_version") != 1
            or bundle.get("status") != PACKET_STATUS
            or bundle.get("review_cases") != 7
            or bundle.get("distinct_security_families") != 7
            or bundle.get("external_source_and_test_file_blob_pairs_verified") != 8
            or bundle.get("fresh_project_holdout_reused") is not False
            or bundle.get("research_only") is not True
            or bundle.get("independent_human_labels") != 0
            or bundle.get("accepted_training_pairs") != 0
            or bundle.get("network_eligible") is not False
            or bundle.get("registered_evaluator") is not False):
        raise ReviewError("bundle is not the quarantined Phase 3F seven-family source report")
    rows = bundle.get("review_packets")
    if not isinstance(rows, list) or len(rows) != 7:
        raise ReviewError("expected seven pinned review questions")
    pins = {item[0]: item for item in PINS}
    if len(pins) != 7 or {p.get("packet_id") for p in rows if isinstance(p, dict)} != set(pins):
        raise ReviewError("wrong source identity set or duplicate packet")
    for p in rows:
        ident = p["packet_id"]
        _, repo, commit, source_blob, test_blob = pins[ident]
        if (p.get("repository") != repo or p.get("fix_commit") != commit
                or p.get("source_post_fix_git_blob_sha1") != source_blob
                or p.get("regression_test_post_fix_git_blob_sha1") != test_blob
                or p.get("human_preference") is not None
                or p.get("human_review_verified") is not False
                or p.get("candidate_order_human_randomized") is not False
                or p.get("source_patch_is_exploit_proof") is not False
                or p.get("production_app_version_known") is not False
                or p.get("production_traffic_exposure_known") is not False
                or p.get("training_authorized") is not False
                or p.get("network_eligible") is not False
                or p.get("label_status") != "AUTHOR_DRAFT_WITH_REAL_SOURCE_NOT_ADJUDICATED"
                or not isinstance(p.get("source_patch_sha256"), str)
                or not HEX64.fullmatch(p["source_patch_sha256"])
                or not isinstance(p.get("regression_test_patch_sha256"), str)
                or not HEX64.fullmatch(p["regression_test_patch_sha256"])):
            raise ReviewError("upstream source/test pin or quarantine status was changed")
        answers = p.get("unreviewed_candidates")
        if (not isinstance(answers, list) or len(answers) != 2
                or [a.get("id") for a in answers if isinstance(a, dict)] != ["A", "B"]):
            raise ReviewError("candidate answer structure changed")
        for answer in answers:
            if (not isinstance(answer.get("text"), str)
                    or not isinstance(answer.get("sha256"), str)
                    or hashlib.sha256(answer["text"].encode("utf-8")).hexdigest() != answer["sha256"]):
                raise ReviewError("candidate answer text hash mismatch")
        for field, expected in (
            ("source_url", f"https://github.com/{repo}/blob/{commit}/{p.get('source_file')}"),
            ("test_url", f"https://github.com/{repo}/blob/{commit}/{p.get('regression_test_file')}"),
        ):
            if p.get(field) != expected or ".." in expected:
                raise ReviewError("source or regression test link is not bound to pinned commit")
    return {p["packet_id"]: p for p in rows}


def blank_templates(bundle: dict) -> dict:
    packets = check_bundle(bundle)
    digest = sha(bundle)
    return {
        "status": "REVIEWER_EXAMPLES_ONLY_NOT_SUBMITTED_OR_VERIFIED",
        "issue_url": ISSUE_WEB,
        "instructions": "Copy exactly one JSON example into GitHub issue #3 fenced as falsum-review-v1. Replace both placeholder prose fields with independently checked reasoning. This is public feedback, not an expert label.",
        "examples": [{
            "packet_id": ident,
            "github_comment_markdown": "```falsum-review-v1\n" + json.dumps({
                "schema_version": 1, "packet_bundle_sha256": digest,
                "packet_id": ident,
                "candidate_answer_sha256": [a["sha256"] for a in p["unreviewed_candidates"]],
                "preference": "ABSTAIN", "source_url": p["source_url"],
                "test_url": p["test_url"],
                "reasoning": "REPLACE WITH YOUR OWN SOURCE-AND-TEST-GROUNDED EXPLANATION",
                "unresolved_facts": "REPLACE WITH SPECIFIC UNPROVEN DEPLOYMENT ASSUMPTIONS",
            }, indent=2) + "\n```",
        } for ident, p in sorted(packets.items())],
    }


def _get_page(page: int) -> list[dict]:
    url = f"{ISSUE_API}/comments?per_page=100&page={page}"
    headers = {
        "Accept": "application/vnd.github+json", "User-Agent": "falsum-phase3g-public-review",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as resp:
        if resp.geturl() != url:
            raise ReviewError("comment API redirected away from expected public GitHub URL")
        body = resp.read(2_000_001)
    if len(body) > 2_000_000:
        raise ReviewError("GitHub page exceeded bounded response size")
    result = json.loads(body)
    if not isinstance(result, list) or len(result) > 100:
        raise ReviewError("GitHub comment page is malformed")
    return result


def _parse_claim(comment: dict, packets: dict, digest: str) -> tuple[dict | None, str | None]:
    body = comment.get("body")
    if not isinstance(body, str) or len(body) > 12000:
        return None, "invalid_comment_body"
    matches = TAG.findall(body)
    if not matches:
        return None, None  # unrelated public discussion is not a failed review
    if len(matches) != 1:
        return None, "multiple_review_blocks"
    try:
        claim = json.loads(matches[0])
    except (ValueError, TypeError):
        return None, "invalid_review_json"
    if not isinstance(claim, dict) or set(claim) != SUBMISSION_KEYS:
        return None, "unknown_or_missing_review_fields"
    ident = claim.get("packet_id")
    if not isinstance(ident, str) or ident not in packets:
        return None, "unknown_packet"
    p = packets[ident]
    if (type(claim["schema_version"]) is not int or claim["schema_version"] != 1
            or claim["packet_bundle_sha256"] != digest
            or claim["candidate_answer_sha256"] != [a["sha256"] for a in p["unreviewed_candidates"]]
            or claim["source_url"] != p["source_url"]
            or claim["test_url"] != p["test_url"]):
        return None, "stale_or_tampered_source_binding"
    if claim["preference"] not in ("A", "B", "ABSTAIN"):
        return None, "invalid_preference"
    for field in ("reasoning", "unresolved_facts"):
        val = claim[field]
        if (not isinstance(val, str) or not 40 <= len(val) <= 3000
                or "REPLACE WITH" in val or "\x00" in val):
            return None, "missing_or_invalid_review_reasoning"
    return {
        "packet_id": ident, "preference_claim": claim["preference"],
        "reasoning_sha256": hashlib.sha256(claim["reasoning"].encode()).hexdigest(),
        "unresolved_facts_sha256": hashlib.sha256(claim["unresolved_facts"].encode()).hexdigest(),
    }, None


def ingest(bundle: dict, pages: list[list[dict]], *, github_api_fetched: bool = False) -> dict:
    """Process caller-supplied API comments. Only production CLI sets fetched=True after HTTPS."""
    packets = check_bundle(bundle)
    digest = sha(bundle)
    if not isinstance(pages, list) or len(pages) > 10:
        raise ReviewError("GitHub page limit exceeded")
    seen_comments: set[int] = set()
    candidates = []
    rejected = []
    scanned = 0
    for page in pages:
        if not isinstance(page, list) or len(page) > 100:
            raise ReviewError("malformed comment page")
        for c in page:
            scanned += 1
            if not isinstance(c, dict) or type(c.get("id")) is not int or c["id"] <= 0:
                raise ReviewError("malformed GitHub comment identity")
            cid = c["id"]
            if cid in seen_comments:
                raise ReviewError("duplicate GitHub issue comment across pages")
            seen_comments.add(cid)
            url = f"{ISSUE_WEB}#issuecomment-{cid}"
            user = c.get("user")
            if (c.get("html_url") != url or c.get("issue_url") != ISSUE_API
                    or not isinstance(user, dict) or user.get("type") != "User"
                    or not isinstance(user.get("login"), str)
                    or type(user.get("id")) is not int or user["id"] <= 0):
                raise ReviewError("comment not attributable to expected GitHub issue")
            login = user["login"]
            claim, reason = _parse_claim(c, packets, digest)
            if claim is None:
                if reason:
                    rejected.append({"comment_url": url, "reason": reason})
                continue
            if login.lower() == "iniwura":
                rejected.append({"comment_url": url, "reason": "project_owner_not_external"})
                continue
            claim.update({
                "comment_url": url, "github_author": login,
                "github_author_id": user["id"],
                "github_attribution_checked_via_api": github_api_fetched,
                "independent_reviewer_verified": False,
                "appsec_expertise_verified": False,
                "underlying_security_claims_verified": False,
                "training_eligible": False,
            })
            candidates.append(claim)
    pairs: dict[tuple[str,int], list[dict]] = {}
    for c in candidates:
        pairs.setdefault((c["packet_id"], c["github_author_id"]), []).append(c)
    duplicate_pairs = {key for key, group in pairs.items() if len(group) != 1}
    for key in duplicate_pairs:
        for c in pairs[key]:
            c["duplicate_review_for_packet"] = True
    clean = [c for c in candidates if (c["packet_id"], c["github_author_id"]) not in duplicate_pairs]
    prefs = {ident: sorted({c["preference_claim"] for c in clean if c["packet_id"] == ident}) for ident in sorted(packets)}
    return {
        "schema_version": 1, "status": STATUS, "bundle_sha256": digest,
        "github_comments_retrieved_via_https": github_api_fetched,
        "github_issue_url": ISSUE_WEB,
        "comments_scanned": scanned, "structured_review_claims": len(candidates),
        "unique_nonowner_github_author_ids": len({c["github_author_id"] for c in candidates}),
        "rejected_review_blocks": rejected,
        "duplicate_author_packet_groups": len(duplicate_pairs),
        "claimed_preference_sets_excluding_duplicates": prefs,
        "unresolved_A_B_disagreements": sum("A" in v and "B" in v for v in prefs.values()),
        "unresolved_abstentions": sum(c["preference_claim"] == "ABSTAIN" for c in clean),
        "claims": sorted(candidates, key=lambda x: (x["packet_id"], x["github_author_id"], x["comment_url"])),
        "independently_verified_expert_labels": 0,
        "accepted_training_pairs": 0, "accepted_network_evaluation_rows": 0,
        "registered_evaluator": False, "network_eligible": False,
        "warning": "GitHub comment authorship does not establish AppSec expertise, independence, correctness, ground truth or Telegraph eligibility. No training or model release is authorized.",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Read public FALSUM #3 reviews; never promote comments to expert labels")
    ap.add_argument("--packets", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--templates-out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        if args.out.exists() or args.templates_out.exists() or args.out == args.templates_out:
            raise ReviewError("will not overwrite report/templates or mix their destinations")
        bundle = json.loads(args.packets.read_text(encoding="utf-8"))
        templates = blank_templates(bundle)
        pages = []
        for n in range(1, 11):
            page = _get_page(n)
            pages.append(page)
            if len(page) < 100:
                break
        else:
            raise ReviewError("more than ten pages of public review comments; refusing partial snapshot")
        result = ingest(bundle, pages, github_api_fetched=True)
        for path, doc in ((args.out, result), (args.templates_out, templates)):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(canonical(doc))
        print(json.dumps({"comments_scanned": result["comments_scanned"],
            "structured_claims": result["structured_review_claims"],
            "expert_labels": 0, "training_pairs": 0, "network_eligible": False}, indent=2))
        return 0
    except (ReviewError, ValueError, TypeError, KeyError, OSError) as exc:
        ap.exit(1, f"FALSUM PUBLIC REVIEW INTAKE FAILED CLOSED: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
