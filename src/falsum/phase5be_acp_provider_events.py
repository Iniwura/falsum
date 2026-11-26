"""Plan a FALSUM provider response from authenticated ACP event evidence.

This module is deliberately prepare-only.  It consumes the JSON envelopes
produced by ``acp events drain`` (or equivalent SDK event envelopes), binds
the buyer requirement to the provider job, and delegates funded-job
preparation to :mod:`phase5bd_acp_provider_prepare`.

It never calls an ACP mutation.  In particular, the returned budget and
submission commands are plans for an authorized operator, not instructions
that this module executes.  A live caller must still obtain the authenticated
history and independently verified Telegraph purchase custody.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any

from . import phase5au_solana_anchor_evidence as anchor
from . import phase5bd_acp_provider_prepare as provider
from . import phase5bb_acp_security_acceptance as gate
from .phase5aj_cross_app_evidence import git_blob, parse, require, source_bytes

ROOT = Path(__file__).resolve().parents[2]
LOCK_PATH = ROOT / "data/phase5be-acp-provider-events-protocol.json"
LOCK = "2ebfea2c2d47210a38141a1e13159e26097fc979"
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
JOB_ID = re.compile(r"[1-9][0-9]{0,77}")
EVENT_TYPES = {
    "job.created", "budget.set", "job.funded", "job.submitted",
    "job.completed", "job.rejected", "job.expired",
}
TERMINAL = {"job.completed", "job.rejected", "job.expired"}


def protocol() -> dict[str, Any]:
    raw = LOCK_PATH.read_bytes()
    require(git_blob(raw) == LOCK, "provider event protocol changed")
    return parse(raw)


def _as_events(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and set(raw) == {"events"}:
        raw = raw["events"]
    require(isinstance(raw, list), "event input must be a list or {events: [...]}")
    require(len(raw) <= 1000, "too many events")
    require(all(isinstance(item, dict) for item in raw), "invalid event envelope")
    return raw


def _identity(value: Any, field: str) -> str:
    require(isinstance(value, str), f"{field} must be a string")
    require(ADDRESS.fullmatch(value) is not None, f"{field} must be an EVM address")
    return value


def normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize an ACP CLI/SDK event envelope without trusting local state."""
    entry = raw.get("entry", raw)
    require(isinstance(entry, dict), "event entry must be an object")
    kind = entry.get("kind")
    require(kind in ("system", "message"), "unknown ACP entry kind")
    chain_id = raw.get("chainId", entry.get("chainId"))
    job_id = raw.get("jobId", entry.get("onChainJobId"))
    require(type(chain_id) is int and chain_id > 0, "invalid event chain id")
    require(isinstance(job_id, str) and JOB_ID.fullmatch(job_id), "invalid event job id")
    roles = raw.get("roles", [])
    tools = raw.get("availableTools", [])
    require(isinstance(roles, list) and all(isinstance(x, str) for x in roles), "invalid roles")
    require(isinstance(tools, list) and all(isinstance(x, str) for x in tools), "invalid available tools")

    out: dict[str, Any] = {
        "chain_id": chain_id,
        "job_id": job_id,
        "kind": kind,
        "roles": roles,
        "available_tools": tools,
        "entry": entry,
    }
    if kind == "system":
        event = entry.get("event")
        require(isinstance(event, dict), "system event must be an object")
        event_type = event.get("type")
        require(event_type in EVENT_TYPES, "unknown ACP system event")
        reported_job_id = event.get("jobId", job_id)
        require(reported_job_id == job_id, "event job id mismatch")
        out["event_type"] = event_type
        out["event"] = event
    else:
        content_type = entry.get("contentType")
        require(content_type in ("text", "proposal", "deliverable", "structured", "requirement"),
                "unknown ACP message content type")
        sender = entry.get("from")
        out["content_type"] = content_type
        out["sender"] = sender
        out["content"] = entry.get("content")
    return out


def _plan(base: dict[str, Any], action: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {
        "schema": "falsum.acp.provider.event-plan.v1",
        "chain_id": base["chain_id"],
        "job_id": base["job_id"],
        "event_type": base.get("event_type"),
        "action": action,
        "reason": reason,
        "mutation_executed": False,
        "requires_authorized_operator": action in {"READY_FOR_BUDGET", "READY_TO_SUBMIT"},
        **extra,
    }


def _refuse(base: dict[str, Any], reason: str) -> dict[str, Any]:
    return _plan(base, "HOLD", reason)


def _history_key(chain_id: int, job_id: str) -> tuple[int, str]:
    return chain_id, job_id


def plan_events(
    raw_events: Any,
    *,
    provider_wallet: str,
    histories: dict[tuple[int, str], dict[str, Any]] | None = None,
    custodies: dict[tuple[int, str], dict[str, Any] | None] | None = None,
    advisory_bytes: bytes | None = None,
) -> list[dict[str, Any]]:
    """Return safe action plans for an ordered event batch.

    ``histories`` and ``custodies`` are caller-owned evidence.  The event
    stream is never treated as authenticated by this module; the operator
    must obtain it from the authenticated provider session and retain the
    raw source separately.
    """
    provider_wallet = _identity(provider_wallet, "provider_wallet")
    histories = histories or {}
    custodies = custodies or {}
    raw = _as_events(raw_events)
    states: dict[tuple[int, str], dict[str, Any]] = {}
    plans: list[dict[str, Any]] = []
    for item in raw:
        try:
            event = normalize(item)
        except (TypeError, ValueError, KeyError) as exc:
            # No job identity is safe to invent from an invalid envelope.
            plans.append({"schema": "falsum.acp.provider.event-plan.v1",
                          "action": "HOLD", "reason": f"INVALID_EVENT:{exc}",
                          "mutation_executed": False,
                          "requires_authorized_operator": False})
            continue
        key = _history_key(event["chain_id"], event["job_id"])
        base = event
        state = states.setdefault(key, {"created": False, "budget": False,
                                        "funded": False, "terminal": False,
                                        "requirement": None, "buyer": None,
                                        "provider": None})
        if "provider" not in event["roles"] and event.get("kind") == "system":
            plans.append(_refuse(base, "PROVIDER_ROLE_NOT_PRESENT"))
            continue

        if event["kind"] == "message":
            if event["content_type"] != "requirement":
                plans.append(_plan(base, "WAIT", "NON_REQUIREMENT_MESSAGE"))
                continue
            try:
                sender = _identity(event["sender"], "requirement sender")
                requirement = parse(str(event["content"]).encode("utf-8"))
            except (TypeError, ValueError, KeyError, UnicodeError, RecursionError) as exc:
                plans.append(_refuse(base, f"MALFORMED_REQUIREMENT:{exc}"))
                continue
            if state["buyer"] is not None and sender.lower() != state["buyer"].lower():
                plans.append(_refuse(base, "BUYER_CHANGED_MID_JOB"))
                continue
            if state["requirement"] is not None:
                plans.append(_refuse(base, "DUPLICATE_REQUIREMENT"))
                continue
            if (not gate.exact_fields(requirement, {"schema", "offering", "report_job", "report"})
                    or requirement.get("schema") != provider.REQUEST_SCHEMA):
                plans.append(_refuse(base, "UNSUPPORTED_VERIFICATION_REQUEST"))
                continue
            state["requirement"] = requirement
            state["buyer"] = sender
            if requirement.get("offering") != provider.OFFERING:
                plans.append(_refuse(base, "WRONG_OFFERING"))
                continue
            plans.append(_plan(base, "READY_FOR_BUDGET", "SUPPORTED_REQUIREMENT",
                               buyer=sender, offering=provider.OFFERING,
                               amount="0.01", requirement_digest=gate.digest(requirement),
                               command="acp provider set-budget --job-id " + event["job_id"]
                               + " --amount 0.01 --chain-id " + str(event["chain_id"])
                               + " --json"))
            continue

        system = event["event"]
        if system.get("provider") is not None:
            try:
                observed_provider = _identity(system["provider"], "event provider")
            except (TypeError, ValueError, KeyError) as exc:
                plans.append(_refuse(base, f"INVALID_PROVIDER_IDENTITY:{exc}"))
                continue
            if observed_provider.lower() != provider_wallet.lower():
                plans.append(_refuse(base, "PROVIDER_IDENTITY_MISMATCH"))
                continue
            state["provider"] = observed_provider
        event_type = event["event_type"]
        if event_type == "job.created":
            if state["created"]:
                plans.append(_refuse(base, "DUPLICATE_JOB_CREATED"))
                continue
            state["created"] = True
            state["buyer"] = system.get("client") or state["buyer"]
            plans.append(_plan(base, "WAIT_FOR_REQUIREMENT", "JOB_CREATED"))
        elif event_type == "budget.set":
            if not state["created"] or state["requirement"] is None:
                plans.append(_refuse(base, "BUDGET_BEFORE_BOUND_REQUIREMENT"))
                continue
            if state["budget"]:
                plans.append(_refuse(base, "DUPLICATE_BUDGET"))
                continue
            state["budget"] = True
            plans.append(_plan(base, "WAIT_FOR_FUNDING", "BUDGET_SET"))
        elif event_type == "job.funded":
            if (not state["created"] or state["requirement"] is None
                    or not state["budget"] or state["funded"]):
                plans.append(_refuse(base, "FUNDED_BEFORE_EXACT_LIFECYCLE"))
                continue
            if "submit" not in event["available_tools"]:
                plans.append(_refuse(base, "SUBMIT_TOOL_NOT_AUTHORIZED_BY_EVENT"))
                continue
            state["funded"] = True
            history = histories.get(key)
            if history is None:
                plans.append(_refuse(base, "AUTHENTICATED_HISTORY_REQUIRED"))
                continue
            context = {
                "chain_id": event["chain_id"],
                "job_id": event["job_id"],
                "buyer": state["buyer"],
                "offering": provider.OFFERING,
                "requirement_digest": gate.digest(state["requirement"]),
            }
            custody = custodies.get(key)
            raw_advisory = advisory_bytes
            if raw_advisory is None:
                source = next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory")
                raw_advisory = source_bytes(source)
            try:
                prepared = provider.prepare(context, history, custody, raw_advisory)
            except (TypeError, ValueError, KeyError, UnicodeError, RecursionError) as exc:
                plans.append(_refuse(base, f"PREPARATION_ERROR:{exc}"))
                continue
            if not prepared.get("prepared"):
                plans.append(_refuse(base, prepared.get("reason", "PREPARATION_REFUSED")))
                continue
            deliverable = prepared["deliverable"]
            plans.append(_plan(base, "READY_TO_SUBMIT", "FUNDED_JOB_PREPARED",
                               recommendation=deliverable["report_evaluation"]["recommendation"],
                               deliverable=deliverable,
                               command="acp provider submit --job-id " + event["job_id"]
                               + " --deliverable <prepared-json> --chain-id " + str(event["chain_id"])
                               + " --json"))
        elif event_type == "job.submitted":
            plans.append(_plan(base, "WAIT_FOR_OUTCOME", "DELIVERABLE_SUBMITTED"))
        elif event_type in TERMINAL:
            state["terminal"] = True
            plans.append(_plan(base, "CLOSE", "TERMINAL_EVENT"))
    return plans


def _load_json(path: Path) -> Any:
    raw = path.read_bytes()
    require(len(raw) <= 2_000_000, "input exceeds byte limit")
    return parse(raw)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--events", type=Path, required=True,
                   help="JSON list or acp events drain JSON envelope")
    p.add_argument("--provider-wallet", required=True)
    p.add_argument("--history", type=Path,
                   help="optional funded history JSON for the single job in the event batch")
    p.add_argument("--trusted-custody", type=Path,
                   help="optional caller-verified Telegraph custody JSON")
    p.add_argument("--advisory", type=Path)
    args = p.parse_args()
    protocol()
    events = _load_json(args.events)
    histories: dict[tuple[int, str], dict[str, Any]] = {}
    custodies: dict[tuple[int, str], dict[str, Any] | None] = {}
    if args.history:
        history = _load_json(args.history)
        histories[(history["chainId"], history["jobId"])] = history
    if args.trusted_custody:
        custody = _load_json(args.trusted_custody)
        if args.history:
            custodies[(history["chainId"], history["jobId"])] = custody
    advisory = args.advisory.read_bytes() if args.advisory else None
    print(json.dumps(plan_events(events, provider_wallet=args.provider_wallet,
                                 histories=histories, custodies=custodies,
                                 advisory_bytes=advisory), sort_keys=True,
                     allow_nan=False))


if __name__ == "__main__":
    main()
