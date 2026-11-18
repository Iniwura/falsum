"""Phase 4N: verify the operator-shown Anjoman Privy wallet, not a stale /submit wallet.

Only GET public contributor rows for two *distinct* Ethereum addresses and emit
count/status aggregates. Never disclose response bodies, row IDs, prompt
content, A/B answers, signatures, private keys, or an assertion of ownership.

Operator supplied the account's public Privy wallet address on November 18;
this correspondence is a user observation, NOT a cryptographic identity proof.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re

from .phase4k_submission_readback import (
    COMMENT_PUBLIC_LINK, COMMENT_URL, INTENT, NODE_URL, REPORTED_ROWS,
    ReadbackError, _collect_status, _extract_comment, _fetch_json,
)

# PUBLIC wallet address shown by the user in Anjoman's Privy Wallet panel.
# NOT a secret, signing key, smart-wallet address, or a verified owner proof.
PRIVY_ADDRESS = "0xd2f5949cd950026a2960639ababa89a699ace4e6"
PUBLIC_BOUNTY_ADDRESS = "0x9cBA6Cf94A42F72B1d4e0bDca151C1343d8DFa02"
ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
STATUS = "PHASE4N_OPERATOR_PRIVY_VS_OLD_PUBLIC_SUBMITTER_READ_ONLY"
MAX_ROWS = 5000


class ContributorReadbackError(ValueError):
    pass


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ContributorReadbackError(reason)


def account_readback(address: str, fetch) -> dict:
    require(isinstance(address, str) and ADDR.fullmatch(address) is not None,
            "invalid Ethereum address")
    counts, count = _collect_status(address, fetch)
    retry = False
    if count == 0 and address != address.lower():
        lowercase, lower_total = _collect_status(address.lower(), fetch)
        retry = True
        if lower_total:
            counts, count = lowercase, lower_total
    require(sum(counts.values()) == count, "mismatched response status counts")
    return {
        "readback_completed": True,
        "current_total_rows": count,
        "current_eligible_rows": counts.get("eligible", 0),
        "counts_by_state": {k: counts.get(k, 0) for k in sorted(
            ("eligible", "admitted", "quarantine", "rejected", "superseded", "revoked"))},
        "lowercase_retry_used": retry,
        "source_address_fingerprint_sha256": hashlib.sha256(
            address.lower().encode("ascii")).hexdigest(),
        "node_endpoint": NODE_URL,
    }


def unavailable_readback(address: str, exc: Exception) -> dict:
    return {
        "readback_completed": False,
        "current_total_rows": None,
        "current_eligible_rows": None,
        "counts_by_state": None,
        "lowercase_retry_used": None,
        "source_address_fingerprint_sha256": hashlib.sha256(
            address.lower().encode("ascii")).hexdigest(),
        "node_endpoint": NODE_URL,
        "error_type": type(exc).__name__,
    }


def report(fetch=None, *, privy_address: str = PRIVY_ADDRESS) -> dict:
    if fetch is None:
        fetch = _fetch_json
    require(isinstance(privy_address, str) and ADDR.fullmatch(privy_address) is not None,
            "invalid operator-supplied public wallet address")
    # A temporary unauthenticated GitHub API failure must not prevent the
    # independently scoped Anjoman Privy-wallet query. Preserve the precise
    # distinction: the historical public comment address was independently
    # observed earlier, but its *current* comment readback may be unavailable.
    comment_address = PUBLIC_BOUNTY_ADDRESS
    comment_sha = None
    comment_check = "GITHUB_COMMENT_FETCH_UNAVAILABLE_OR_CHANGED"
    try:
        comment = fetch(COMMENT_URL, 100_000)
        current_address, comment_sha = _extract_comment(comment)
        if current_address.lower() == PUBLIC_BOUNTY_ADDRESS.lower():
            comment_check = "LIVE_COMMENT_MATCHES_ORIGINAL_RECORDED_ADDRESS"
        else:
            comment_check = "LIVE_COMMENT_ADDRESS_DIFFERENT_FROM_HISTORICAL"
    except (ReadbackError, OSError, ValueError, TypeError,
            UnicodeError, json.JSONDecodeError):
        pass
    require(comment_address.lower() != privy_address.lower(),
            "historical bounty address and operator Privy address must differ")
    results = {}
    for role, address in (("signed_in_privy_wallet_user_observed", privy_address),
                          ("historical_bounty_comment_wallet", comment_address)):
        try:
            results[role] = account_readback(address, fetch)
        except (ReadbackError, OSError, ValueError, TypeError, UnicodeError,
                json.JSONDecodeError) as exc:
            results[role] = unavailable_readback(address, exc)
    privy = results["signed_in_privy_wallet_user_observed"]
    old = results["historical_bounty_comment_wallet"]
    if privy["readback_completed"] and privy["current_eligible_rows"] == REPORTED_ROWS:
        finding = "OPERATOR_SHOWN_PRIVY_ADDRESS_HAS_20_ELIGIBLE_ROWS_IN_PUBLIC_NODE"
    elif privy["readback_completed"]:
        finding = "OPERATOR_SHOWN_PRIVY_ADDRESS_LIVE_STATUS_DIFFERS_FROM_HISTORICAL_20"
    else:
        finding = "OPERATOR_SHOWN_PRIVY_ADDRESS_LIVE_READBACK_UNAVAILABLE_UNKNOWN"
    return {
        "schema_version": 1,
        "status": STATUS,
        "finding": finding,
        "intent_id": INTENT,
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "source_comment_url": COMMENT_PUBLIC_LINK,
        "source_comment_sha256": comment_sha,
        "current_comment_verification_status": comment_check,
        "historical_account_displayed_eligible_rows_reported_by_user": REPORTED_ROWS,
        "addresses_distinct": True,
        "accounts": results,
        "operator_association_is_based_on_user_provided_anjo_wallet_panel": True,
        "cryptographic_wallet_ownership_verified": False,
        "accepted_bounty_verified": False,
        "registered_evaluator_verified": False,
        "independent_appsec_gold_labels_verified": 0,
        "public_api_row_status_is_not_expert_review_or_pool_snapshot_membership": True,
        "private_rows_persisted_or_logged": False,
        "privacy_note": (
            "Reports only aggregate state counts, SHA256 fingerprints of public addresses "
            "and validation limits. Two distinct public wallets do not establish signer "
            "ownership; a matching count does not establish label quality, payout, "
            "maintainer acceptance or formal H2 submission."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only public Privy-vs-bounty-wallet status check")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args(argv)
    if args.out.is_symlink() or args.out.exists():
        p.error("refusing overwrite of prior verification evidence")
    try:
        data = report()
    except (ContributorReadbackError, OSError, ValueError, TypeError,
            UnicodeError, json.JSONDecodeError) as exc:
        data = {
            "schema_version": 1,
            "status": STATUS,
            "finding": "PUBLIC_GITHUB_COMMENT_OR_SOURCE_UNAVAILABLE_UNKNOWN",
            "intent_id": INTENT,
            "observed_utc": datetime.now(timezone.utc).isoformat(),
            "accounts": None,
            "source_comment_url": COMMENT_PUBLIC_LINK,
            "error_type": type(exc).__name__,
            "private_rows_persisted_or_logged": False,
            "accepted_bounty_verified": False,
            "cryptographic_wallet_ownership_verified": False,
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        json.dump(data, out, indent=2, sort_keys=True)
        out.write("\n")
    public_summary = {
        "status": data["status"], "finding": data["finding"],
        "error_type": data.get("error_type"),
        "intent_id": INTENT, "private_rows_persisted_or_logged": False,
        "report_file_written": str(args.out),
    }
    if isinstance(data.get("accounts"), dict):
        for role, entry in data["accounts"].items():
            public_summary[role] = {
                "readback_completed": entry["readback_completed"],
                "eligible_rows": entry["current_eligible_rows"],
                "total_rows": entry["current_total_rows"],
            }
    print(json.dumps(public_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
