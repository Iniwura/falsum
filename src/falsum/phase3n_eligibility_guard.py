"""Phase 3N: offline, privacy-preserving verification of Anjoman /mine status.

NEVER infer 'eligible' from an upload's 'stored' or 'admitted' count.
Anjoman returns per-contributor row hashes; these must stay private,
along with wallet addresses and hidden evaluation question/answer contents.

This script reads a LOCAL copy of the real /api/evalpool/submissions/mine
response. It performs no outbound requests, wallet operations, uploads or
bounty submissions. Output is aggregate counts without row identities.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re

INTENT = "SECURITY_REVIEW_GENERAL"
STATES = frozenset(("quarantine","admitted","eligible","rejected","superseded","revoked"))
HASH = re.compile(r"^[a-fA-F0-9]{64}$")
WALLET = re.compile(r"^0x[a-fA-F0-9]{40}$")
MAX_FILE = 5_000_000
STATUS = "PHASE3N_REAL_LOCAL_CONTRIBUTOR_STATUS_AGGREGATES_NO_PRIVATE_IDENTITIES"


class ClaimError(ValueError):
    pass


def _get_local(path: Path) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_FILE:
        raise ClaimError("local regular non-symlink status export under 5MB required")
    return json.loads(path.read_text(encoding="utf-8"))


def reduce_mine(record: object, *, expect_rows: int | None = None) -> dict:
    if not isinstance(record, dict) or not WALLET.fullmatch(str(record.get("submitter",""))):
        raise ClaimError("a valid actual contributor wallet in local node response is required")
    if (type(record.get("count")) is not int or record["count"] < 0
            or not isinstance(record.get("rows"),list)
            or len(record["rows"]) != record["count"]):
        raise ClaimError("incomplete or truncated /mine response; all pages required")
    if expect_rows is not None and (type(expect_rows) is not int or expect_rows < 1
                                     or record["count"] != expect_rows):
        raise ClaimError("unexpected contributor count; review pages, ownership or previous uploads")
    if record["count"] > 5000:
        raise ClaimError("more than one /mine API page or unsupported contributor size")
    counts = Counter()
    reasons = Counter()
    unique = set()
    for i, item in enumerate(record["rows"],1):
        if not isinstance(item,dict) or item.get("intent_id") != INTENT:
            raise ClaimError(f"row {i}: mixed intent or malformed status entry")
        state=item.get("status")
        if state not in STATES:
            raise ClaimError(f"row {i}: missing or unknown row state")
        identity=(item.get("row_hash"),item.get("case_id"))
        if (not all(isinstance(h,str) and HASH.fullmatch(h) for h in identity)
                or identity in unique):
            raise ClaimError(f"row {i}: duplicate or malformed row identity")
        unique.add(identity)
        if state in ("rejected","quarantine","superseded","revoked"):
            if item.get("reason_code") is not None:
                if (not isinstance(item["reason_code"],str) or
                        not re.fullmatch(r"[a-z][a-z0-9_]{0,63}",item["reason_code"])):
                    raise ClaimError(f"row {i}: invalid reason code")
                reasons[item["reason_code"]]+=1
        counts[state]+=1
    if sum(counts.values()) != record["count"]:
        raise ClaimError("count reconciliation failed")
    return {
        "schema_version":1, "status":STATUS,
        "intent_id":INTENT, "submitted_rows_in_local_contributor_response":record["count"],
        "counts_by_state":{key:counts.get(key,0) for key in sorted(STATES)},
        "reason_code_counts_only":dict(sorted(reasons.items())),
        "owned_eligible_rows_in_response":counts["eligible"],
        "eligible_network_evidence_present":counts["eligible"] > 0,
        "all_rows_eligible":record["count"]>0 and counts["eligible"] == record["count"],
        "eligible_for_bounty_evaluation_part_claim":counts["eligible"] > 0,
        "bounty_submit_message_posted":False,
        "bounty_maintainer_accepted":False,
        "wallet_or_row_hashes_in_output":False,
        "private_row_text_or_answers_accessed":False,
        "source":"local copy of authenticated-address /mine API response; no independent HTTP verification by this script",
        "notice":"Admitted means curated, NOT eligible. Eligible is confirmed only by explicit status eligible for a contributor's own row. Reconcile against latest Anjoman epoch. Bounty submission and maintainer verification remain separate."
    }


def recorded_screenshot_milestone() -> dict:
    """User-supplied account UI screenshot: no address, timestamped state only."""
    return {
        "schema_version":1,
        "status":"PHASE3N_USER_UI_SCREENSHOT_ATTESTED_ADMITTED_ONLY_NOT_ELIGIBLE",
        "observed_date":"2026-11-02",
        "intent_id":INTENT,
        "source_kind":"user_supplied_account_ui_screenshot_not_public_node_receipt",
        "screen_message":"Sent. 20 stored, 0 already there, 0 refused.",
        "admitted_rows_visible":20,
        "duplicates_reported":0,
        "refused_reported":0,
        "eligible_rows_verified_by_this_screenshot":0,
        "network_owned_eligibility_queried":False,
        "bounty_submitted":False,
        "registered_evaluator":False,
        "screenshot_private_not_committed":True,
        "row_prompts_and_chosen_rejected_private":True,
        "note":"Admitted 20 of 20 on user's Anjoman screen. A pending rollover may later mark some eligible or rejected. Do not claim eligible until inspecting the actual per-contributor status."
    }


def write_private(out: Path, report: dict) -> None:
    if out.exists() or out.is_symlink():
        raise ClaimError("refusing to overwrite existing local status summary")
    out.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as file:
        json.dump(report,file,sort_keys=True,indent=2)
        file.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(description="Validate local Anjoman /mine without leaking wallets, row hashes or hidden questions")
    parser.add_argument("--mine-json",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    parser.add_argument("--expect-rows",type=int)
    a=parser.parse_args(argv)
    try:
        report=reduce_mine(_get_local(a.mine_json),expect_rows=a.expect_rows)
        write_private(a.out,report)
        print(json.dumps(report,sort_keys=True,indent=2))
        return 0
    except (ClaimError,OSError,UnicodeError,ValueError,TypeError,KeyError) as exc:
        parser.exit(1,f"FALSUM PHASE3N ELIGIBILITY CLAIM BLOCKED: {exc}\n")


if __name__=="__main__":
    raise SystemExit(main())
