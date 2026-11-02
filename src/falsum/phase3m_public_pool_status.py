"""Phase 3M: read-only, allowlisted Anjoman SECURITY_REVIEW_GENERAL status witness.

Only the published intent-level endpoint is queried. No wallet, address,
hidden row, signature, training material or submission payload is requested.
Network failures explicitly remain UNKNOWN, never treated as zero eligible.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import urllib.request

INTENT = "SECURITY_REVIEW_GENERAL"
ENDPOINT = "https://devnode.telegraphprotocol.com/api/evalpool/status?intent_id=SECURITY_REVIEW_GENERAL"
STATES = {"quarantine","admitted","eligible","rejected","superseded","revoked"}


class PoolStatusError(ValueError):
    pass


def interpret(data: object) -> dict:
    if not isinstance(data, dict) or data.get("intent_id") != INTENT:
        raise PoolStatusError("node response intent mismatch")
    by_state = data.get("by_state")
    if not isinstance(by_state, dict) or any(k not in STATES or type(v) is not int or v < 0 for k,v in by_state.items()):
        raise PoolStatusError("invalid public status counts")
    for k in ("submitters", "eligible_submitters", "min_submitters", "current_epoch"):
        if type(data.get(k)) is not int or data[k] < 0:
            raise PoolStatusError("missing or invalid public status field "+k)
    if data["eligible_submitters"] > data["submitters"] or data["min_submitters"] < 1:
        raise PoolStatusError("impossible contributor counts")
    for k in ("snapshot","active_snapshot"):
        snap=data.get(k)
        if snap is not None and (not isinstance(snap, dict) or
             not isinstance(snap.get("corpus_version"),str) or
             type(snap.get("rows")) is not int or snap["rows"] < 0 or
             type(snap.get("activation_epoch")) is not int or snap["activation_epoch"] < 0):
            raise PoolStatusError("untrusted or malformed snapshot "+k)
    return {
        "schema_version":1,
        "status":"READ_ONLY_PUBLIC_ANJOMAN_INTENT_POOL_STATUS_NOT_USER_CONTRIBUTION",
        "intent_id":INTENT,
        "node_url":ENDPOINT,
        "public_eligible_rows_in_intent":by_state.get("eligible",0),
        "public_admitted_rows_in_intent":by_state.get("admitted",0),
        "public_quarantine_rows_in_intent":by_state.get("quarantine",0),
        "eligible_submitters":data["eligible_submitters"],
        "minimum_submitters_for_pool":data["min_submitters"],
        "pool_contributor_threshold_reached":data["eligible_submitters"] >= data["min_submitters"],
        "active_snapshot_present":data["active_snapshot"] is not None,
        "active_snapshot_epoch":data["active_snapshot"]["activation_epoch"] if data["active_snapshot"] else None,
        "snapshot_pending_activation":data["snapshot"] is not None and (
            data["active_snapshot"] is None or
            data["snapshot"]["corpus_version"] != data["active_snapshot"]["corpus_version"]
        ),
        "current_epoch":data["current_epoch"],
        "operator_address_was_not_provided":True,
        "falsum_owned_eligible_rows_confirmed":0,
        "own_submission_checked":False,
        "node_response_is_authoritative_only_for_the_public_intent":True,
        "notice":"These public aggregate counts describe the whole intent, never FALSUM ownership. No rows were submitted, endorsed, signed, uploaded or verified as belonging to any contributor."
    }


def load_live() -> dict:
    request=urllib.request.Request(
        ENDPOINT,headers={"Accept":"application/json","User-Agent":"FALSUM-phase3m-readonly-status/1.0"})
    with urllib.request.urlopen(request,timeout=18) as response:
        if response.geturl()!=ENDPOINT or response.status!=200:
            raise PoolStatusError("node redirected or non-200 status")
        data=response.read(180_001)
    if len(data)>180_000:
        raise PoolStatusError("node response over 180 KB")
    return interpret(json.loads(data.decode("utf-8",errors="strict")))


def main(argv:list[str]|None=None)->int:
    p=argparse.ArgumentParser(description="Read only the public security-review intent's pool status")
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args(argv)
    if args.out.exists():
        p.exit(1,"FALSUM: refuse overwriting prior public status witness\n")
    try:
        report=load_live()
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
        print(json.dumps(report,indent=2))
        return 0
    except (PoolStatusError,ValueError,OSError,UnicodeError,json.JSONDecodeError) as exc:
        # Report UNKNOWN explicitly; never use a failed network probe as evidence of 0 rows.
        status={"schema_version":1,"status":"PUBLIC_INTENT_NODE_STATUS_UNAVAILABLE_NOT_ZERO",
            "intent_id":INTENT,"node_url":ENDPOINT,
            "network_access_succeeded":False,"public_eligible_rows_in_intent":None,
            "eligible_submitters":None,"pool_contributor_threshold_reached":None,
            "own_submission_checked":False,"falsum_owned_eligible_rows_confirmed":None,
            "notice":"Cannot verify live aggregate Anjoman intent status. A failed HTTP request is not proof of zero eligible rows.",
            "error_type":type(exc).__name__}
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps(status,sort_keys=True,indent=2)+"\n")
        print(json.dumps(status,indent=2))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
