"""Read-only Anjoman contributor status from a public bounty submission.

The account address is read from the participant's existing public /submit
comment. No credentials, signing, submissions, row contents or row identities
are emitted. Row status does not establish label correctness or bounty approval.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlencode
from urllib.request import Request, urlopen

INTENT = "SECURITY_REVIEW_GENERAL"
COMMENT_URL = "https://api.github.com/repos/telegraphprotocol/bounties/issues/comments/6588168396"
COMMENT_PUBLIC_LINK = "https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396"
NODE_URL = "https://devnode.telegraphprotocol.com/api/evalpool/submissions/mine"
ALLOWED_STATUSES = {"eligible", "admitted", "quarantine", "rejected", "superseded", "revoked"}
REPORTED_ROWS = 20
PAGE_SIZE = 500
MAX_ROWS = 5000
ADDRESS_LINE = re.compile(r"^\*\*Contributor wallet:\*\*\s*`(0x[0-9a-fA-F]{40})`\s*$", re.M)
HEX64 = re.compile(r"^(?:0x)?[0-9a-fA-F]{64}$")


class ReadbackError(ValueError):
    """A source, readback or status count could not be trusted."""


def _fetch_json(url: str, size_limit: int) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json" if url == COMMENT_URL else "application/json",
        "User-Agent": "FALSUM-public-aggregate-readback/1.0",
    })
    with urlopen(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != url:
            raise ReadbackError("non-200 or redirected source")
        raw = response.read(size_limit + 1)
    if len(raw) > size_limit:
        raise ReadbackError("source response exceeds byte cap")
    data = json.loads(raw.decode("utf-8", errors="strict"))
    if not isinstance(data, dict):
        raise ReadbackError("source must be a JSON object")
    return data


def _extract_comment(data: object) -> tuple[str, str]:
    if not isinstance(data, dict) or not isinstance(data.get("user"), dict):
        raise ReadbackError("missing public submission comment")
    if data["user"].get("login") != "Iniwura" or not isinstance(data.get("body"), str):
        raise ReadbackError("public comment author does not match contributor")
    body = data["body"]
    if not body.startswith("/submit") or INTENT not in body:
        raise ReadbackError("expected published submission absent")
    matches = ADDRESS_LINE.findall(body)
    if len(matches) != 1 or f"**{REPORTED_ROWS} source-referenced evaluation preference pairs**" not in body:
        raise ReadbackError("published source address or expected row count changed")
    return matches[0], hashlib.sha256(body.encode("utf-8")).hexdigest()


def _validate_page(data: object, address: str, previous_count: int | None) -> tuple[int, list[dict]]:
    if not isinstance(data, dict) or str(data.get("submitter", "")).lower() != address.lower():
        raise ReadbackError("node submitter does not match published address")
    count = data.get("count")
    rows = data.get("rows")
    if type(count) is not int or count < 0 or count > MAX_ROWS:
        raise ReadbackError("invalid declared node row count")
    if previous_count is not None and count != previous_count:
        raise ReadbackError("node row count changed during paged readback")
    if not isinstance(rows, list) or len(rows) > PAGE_SIZE:
        raise ReadbackError("invalid node rows payload")
    for row in rows:
        if not isinstance(row, dict) or row.get("intent_id") != INTENT:
            raise ReadbackError("node row from wrong intent")
        if row.get("status") not in ALLOWED_STATUSES:
            raise ReadbackError("unknown node status")
        if not isinstance(row.get("row_hash"), str) or not HEX64.fullmatch(row["row_hash"]):
            raise ReadbackError("missing or invalid row identity")
    return count, rows


def readback(fetch=_fetch_json) -> dict:
    comment = fetch(COMMENT_URL, 100_000)
    address, comment_sha = _extract_comment(comment)
    counts: Counter[str] = Counter()
    seen: set[str] = set()
    declared_total: int | None = None
    for offset in range(0, MAX_ROWS + 1, PAGE_SIZE):
        query = urlencode({"submitter": address, "intent_id": INTENT,
                           "limit": PAGE_SIZE, "offset": offset})
        data = fetch(f"{NODE_URL}?{query}", 2_000_000)
        total, rows = _validate_page(data, address, declared_total)
        declared_total = total
        if offset >= total:
            if rows:
                raise ReadbackError("unexpected rows after reported total")
            break
        if not rows or len(rows) > total - offset:
            raise ReadbackError("truncated or inconsistent page")
        for row in rows:
            row_id = row["row_hash"].lower().removeprefix("0x")
            if row_id in seen:
                raise ReadbackError("duplicate row across pages")
            seen.add(row_id)
            counts[row["status"]] += 1
        if len(seen) == total:
            break
        if len(rows) != PAGE_SIZE:
            raise ReadbackError("incomplete intermediate page")
    if declared_total is None or len(seen) != declared_total:
        raise ReadbackError("incomplete paginated network readback")
    eligible = counts["eligible"]
    if eligible == REPORTED_ROWS:
        status = "PUBLIC_SUBMITTER_ROW_COUNT_MATCHES_REPORTED_20_ELIGIBLE"
    elif eligible > REPORTED_ROWS:
        status = "PUBLIC_SUBMITTER_HAS_MORE_THAN_20_ELIGIBLE_ROWS"
    else:
        status = "PUBLIC_SUBMITTER_HAS_FEWER_THAN_20_ELIGIBLE_ROWS"
    return {
        "schema_version": 1,
        "status": status,
        "intent_id": INTENT,
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "source_public_submission_comment": COMMENT_PUBLIC_LINK,
        "source_comment_sha256": comment_sha,
        "read_only_node_endpoint": NODE_URL,
        "reported_eligible_rows": REPORTED_ROWS,
        "current_total_rows_for_public_comment_address": declared_total,
        "current_eligible_rows_for_public_comment_address": eligible,
        "current_status_counts": {k: counts[k] for k in sorted(ALLOWED_STATUSES)},
        "live_readback_completed": True,
        "comment_is_cryptographic_address_ownership_proof": False,
        "row_content_or_identifiers_in_report": False,
        "independent_expert_semantic_validation": False,
        "maintainer_approval_verified": False,
        "registered_adapter_verified": False,
        "note": "Read-only network statuses for address stated by contributor in a public GitHub /submit. Not maintainer acceptance, verification of identity ownership, expert labels, improved model scoring or final H2 entry. No row hashes, case IDs, questions, answers or account address emitted.",
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read only public Anjoman contributor status and safely summarize counts")
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args(argv)
    if args.out.is_symlink() or args.out.exists():
        p.error("output exists; do not overwrite a previous witness")
    try:
        report = readback()
    except (ReadbackError, OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        report = {
            "schema_version": 1,
            "status": "LIVE_CONTRIBUTOR_READBACK_UNAVAILABLE_NOT_ZERO",
            "intent_id": INTENT,
            "source_public_submission_comment": COMMENT_PUBLIC_LINK,
            "read_only_node_endpoint": NODE_URL,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "live_readback_completed": False,
            "current_eligible_rows_for_public_comment_address": None,
            "maintainer_approval_verified": False,
            "registered_adapter_verified": False,
            "error_type": type(exc).__name__,
            "note": "Unavailable is unknown, not zero rows. No row contents, identifiers, wallet address or raw HTTP body exposed.",
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
