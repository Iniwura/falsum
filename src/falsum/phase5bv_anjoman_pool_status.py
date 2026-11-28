"""Read-only aggregate status for the SECURITY_REVIEW_GENERAL Anjoman pool.

This never reads a contributor address or row content and never writes to the
network. It reports pool readiness, not use of any particular contributor's
rows.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

INTENT_ID = "SECURITY_REVIEW_GENERAL"
STATUS_URL = (
    "https://devnode.telegraphprotocol.com/api/evalpool/status"
    "?intent_id=SECURITY_REVIEW_GENERAL"
)
MAX_RESPONSE_BYTES = 64 * 1024
TIMEOUT_SECONDS = 20
STATUS = "PHASE5BV_ANJOMAN_AGGREGATE_POOL_STATUS"


class PoolStatusError(ValueError):
    """Raised when the public aggregate status cannot be trusted."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise PoolStatusError(message)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        need(key not in output, "duplicate JSON key")
        output[key] = value
    return output


def _integer(value: object, field: str) -> int:
    need(isinstance(value, int) and not isinstance(value, bool) and value >= 0,
         f"{field} must be a non-negative integer")
    return value


def _snapshot(value: object, field: str) -> dict[str, int] | None:
    if value is None:
        return None
    need(isinstance(value, dict), f"{field} must be an object or null")
    return {
        "rows": _integer(value.get("rows"), f"{field}.rows"),
        "submitters": _integer(value.get("submitters"), f"{field}.submitters"),
        "activation_epoch": _integer(value.get("activation_epoch"), f"{field}.activation_epoch"),
    }


def parse_status(raw: bytes, *, observed_utc: str | None = None) -> dict[str, Any]:
    need(isinstance(raw, bytes) and 0 < len(raw) <= MAX_RESPONSE_BYTES,
         "status response is empty or exceeds the byte cap")
    try:
        payload = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PoolStatusError("status response is not strict UTF-8 JSON") from exc

    need(isinstance(payload, dict), "status response must be an object")
    need(payload.get("intent_id") == INTENT_ID, "status response Intent does not match")

    counts = payload.get("counts")
    need(isinstance(counts, list), "status counts must be a list")
    by_state: dict[str, int] = {}
    for index, item in enumerate(counts):
        need(isinstance(item, dict), f"counts[{index}] must be an object")
        state = item.get("status")
        need(isinstance(state, str) and state and len(state) <= 40,
             f"counts[{index}].status is invalid")
        count = _integer(item.get("count"), f"counts[{index}].count")
        by_state[state] = by_state.get(state, 0) + count

    submitters = _integer(payload.get("submitters"), "submitters")
    eligible_submitters = _integer(payload.get("eligible_submitters"), "eligible_submitters")
    min_submitters = _integer(payload.get("min_submitters"), "min_submitters")
    current_epoch = _integer(payload.get("current_epoch"), "current_epoch")
    latest = _snapshot(payload.get("snapshot"), "snapshot")
    active = _snapshot(payload.get("active_snapshot"), "active_snapshot")

    if latest is not None:
        need(latest["activation_epoch"] >= 0, "snapshot activation epoch is invalid")
    if active is not None:
        need(active["activation_epoch"] <= current_epoch,
             "active snapshot activation epoch is ahead of current epoch")

    active_snapshot_meets_minimum = bool(
        active is not None
        and active["rows"] > 0
        and active["submitters"] >= min_submitters
    )
    latest_snapshot_is_active = bool(
        latest is not None
        and active is not None
        and active["activation_epoch"] >= latest["activation_epoch"]
    )

    return {
        "schema_version": 1,
        "status": STATUS,
        "observed_utc": observed_utc or datetime.now(timezone.utc).isoformat(),
        "intent_id": INTENT_ID,
        "source": {
            "endpoint": STATUS_URL,
            "scope": "aggregate_pool_status_only",
            "row_content_requested": False,
            "contributor_address_requested": False,
            "authenticated": False,
            "network_write_performed": False,
        },
        "pool": {
            "counts_by_state": dict(sorted(by_state.items())),
            "submitters": submitters,
            "eligible_submitters": eligible_submitters,
            "min_submitters": min_submitters,
            "current_epoch": current_epoch,
            "latest_snapshot": latest,
            "active_snapshot": active,
            "active_snapshot_meets_contributor_minimum": active_snapshot_meets_minimum,
            "latest_snapshot_is_active": latest_snapshot_is_active,
            "active_pool_available_for_current_epoch": active_snapshot_meets_minimum,
        },
        "contribution": {
            "operator_rows_in_active_snapshot_verified": False,
            "operator_rows_used_for_ranking_verified": False,
            "maintainer_acceptance_verified": False,
            "evaluator_registration_verified": False,
        },
        "interpretation": (
            "A qualifying active snapshot shows that the aggregate judgment pool is available "
            "for the current epoch. This endpoint does not identify contributors or rows, so it "
            "cannot prove that FALSUM's 20 eligible rows are in the active snapshot or were used."
        ),
        "limits": [
            "Aggregate counts and snapshot metadata only; no wallet address, row identity, prompt, answer or signature is requested or stored.",
            "The per-contributor readback is a separate endpoint and is not called by this check.",
            "The public documentation states there is no public endpoint for per-row ranking-use records.",
            "No maintainer acceptance, canonical evaluator registration, provider ranking change or H2 award is inferred.",
        ],
    }


def fetch_status(fetcher=None) -> bytes:
    if fetcher is not None:
        raw = fetcher(STATUS_URL)
        need(isinstance(raw, bytes), "injected status fetcher must return bytes")
        return raw
    request = Request(
        STATUS_URL,
        headers={
            "Accept": "application/json",
            "User-Agent": "FALSUM-phase5bv-read-only-status/1.0",
        },
    )
    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        need(response.status == 200, "Anjoman status endpoint did not return HTTP 200")
        need(response.geturl() == STATUS_URL, "Anjoman status endpoint redirected unexpectedly")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    need(0 < len(raw) <= MAX_RESPONSE_BYTES, "Anjoman status response exceeds the byte cap")
    return raw


def write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json", "output path must end in .json")
    need(not path.exists() and not path.is_symlink(), "output must be a new path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = parse_status(fetch_status())
        write_once(args.out, report)
        pool = report["pool"]
        print(json.dumps({
            "status": report["status"],
            "intent_id": report["intent_id"],
            "eligible_submitters": pool["eligible_submitters"],
            "minimum_submitters": pool["min_submitters"],
            "active_snapshot": pool["active_snapshot"],
            "active_pool_available_for_current_epoch": pool["active_pool_available_for_current_epoch"],
            "latest_snapshot_is_active": pool["latest_snapshot_is_active"],
            "operator_rows_in_active_snapshot_verified": False,
        }, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(1, "PHASE5BV ANJOMAN STATUS CHECK FAILED: " + str(exc)[:300] + "\\n")


if __name__ == "__main__":
    raise SystemExit(main())
