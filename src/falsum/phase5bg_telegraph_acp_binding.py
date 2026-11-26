"""Fail-closed binding of one Telegraph capture to one ACP verification job.

This module is intentionally verification-only.  It never calls Telegraph,
ACP, an RPC endpoint, a wallet, or a signer.  A caller must retain the raw
HTTP bodies, receipt headers, an independently obtained token-transfer receipt,
the exact ACP requirement bytes, authenticated ACP history, and the exact
deliverable bytes that would be submitted.

The current Phase 5BD request schema is v1 and has no place for this binding.
The strict path below therefore accepts only the explicit v2 extension.  A
v1 request, a receipt without request/response/job links, or a missing original
Telegraph job identifier returns HOLD.  No identifier is generated here.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from . import phase5bb_acp_security_acceptance as gate
from . import phase5bd_acp_provider_prepare as provider


SCHEMA = "falsum.telegraph.acp.binding.v1"
REQUEST_SCHEMA_V2 = provider.REQUEST_SCHEMA_V2
BINDING_REF_SCHEMA = provider.BINDING_REF_SCHEMA
REPORT_SCHEMA_V2 = provider.REPORT_SCHEMA_V2
RESULT_SCHEMA = provider.RESULT_SCHEMA
OFFERING = provider.OFFERING
TELEGRAPH_URL = "https://devnode.telegraphprotocol.com/engine/v1/ask"
TELEGRAPH_INTENT = "SECURITY_REVIEW_GENERAL"
TELEGRAPH_NETWORK = "eip155:84532"
TELEGRAPH_CHAIN_ID = 84532
TELEGRAPH_ASSET = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
TELEGRAPH_PAY_TO = "0xC0A3FB6dF3F1f4B54617d29ffbdA4663Af5F96e2e"
TELEGRAPH_AMOUNT = "10000"
TELEGRAPH_SCHEME = "exact"
ACP_CHAIN_ID = 8453
FALSUM_PROVIDER_WALLET = "0x012501f623e8a45c0de5716d1228d2b61f1b3a0c"
ANCHOR_REQUEST = {
    "intent": TELEGRAPH_INTENT,
    "params": {
        "target": "Review anchor-lang 1.0.1 for GHSA-c6rc-8jpp-2fgc applicability",
    },
}
ANCHOR_REQUEST_BYTES = json.dumps(
    ANCHOR_REQUEST, sort_keys=True, separators=(",", ":"), ensure_ascii=True
).encode("ascii")
ANCHOR_REQUEST_SHA256 = hashlib.sha256(ANCHOR_REQUEST_BYTES).hexdigest()
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}\Z")
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}\Z")
JOB_ID = re.compile(r"[1-9][0-9]{0,77}\Z")
CLASSIFICATIONS = {"CONSTRUCTED_TEST", "LIVE_SELF_CONTROLLED", "LIVE_EXTERNAL_CUSTOMER"}
BINDING_REF_FIELDS = provider.BINDING_REF_FIELDS


class BindingError(ValueError):
    """A deterministic fail-closed reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def digest(value: Any) -> str:
    """Hash the same compact, sorted ASCII JSON used by the Phase 5B gates."""
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BindingError("NON_CANONICAL_JSON") from exc
    return hashlib.sha256(raw).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_constant(value: str) -> None:
    raise ValueError(value)


def _no_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _json_bytes(value: Any, label: str) -> tuple[bytes, Any]:
    if not isinstance(value, str):
        raise BindingError(f"MISSING_{label.upper()}_BYTES")
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
        if len(raw) > 2_000_000:
            raise BindingError(f"{label.upper()}_TOO_LARGE")
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except BindingError:
        raise
    except (UnicodeError, ValueError, binascii.Error, json.JSONDecodeError) as exc:
        raise BindingError(f"MALFORMED_{label.upper()}_JSON") from exc
    return raw, obj


def _hash_field(obj: dict[str, Any], field: str, actual: str, reason: str) -> None:
    value = obj.get(field)
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise BindingError(f"MISSING_{field.upper()}")
    if value != actual:
        raise BindingError(reason)


def _address(value: Any, field: str) -> str:
    if not isinstance(value, str) or ADDRESS.fullmatch(value) is None:
        raise BindingError(f"INVALID_{field.upper()}")
    return value


def _job_id(value: Any, reason: str = "MISSING_ORIGINAL_REPORT_JOB_ID") -> str:
    if not isinstance(value, str) or JOB_ID.fullmatch(value) is None:
        raise BindingError(reason)
    return value


def _exact_fields(value: Any, expected: set[str], reason: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise BindingError(reason)
    return value


def _report_job(value: Any) -> dict[str, Any]:
    try:
        job = _exact_fields(
            value,
            gate.JOB_FIELDS,
            "INVALID_ORIGINAL_REPORT_JOB",
        )
        if job["schema"] != gate.SCHEMA:
            raise BindingError("INVALID_ORIGINAL_REPORT_JOB")
        if type(job["chain_id"]) is not int or job["chain_id"] != TELEGRAPH_CHAIN_ID:
            raise BindingError("ORIGINAL_REPORT_CHAIN_MISMATCH")
        _job_id(job["job_id"])
        if job["intent"] != TELEGRAPH_INTENT:
            raise BindingError("ORIGINAL_REPORT_INTENT_MISMATCH")
        target = _exact_fields(job["target"], gate.TARGET_FIELDS, "INVALID_ORIGINAL_REPORT_TARGET")
        if target != {
            "ecosystem": "crates.io",
            "package": "anchor-lang",
            "version": "1.0.1",
            "reference": "GHSA-c6rc-8jpp-2fgc",
        }:
            raise BindingError("ORIGINAL_REPORT_TARGET_MISMATCH")
    except KeyError as exc:
        raise BindingError("INVALID_ORIGINAL_REPORT_JOB") from exc
    return job


def _quote(quote: Any) -> dict[str, Any]:
    quote = _exact_fields(
        quote,
        {"scheme", "network", "asset", "payTo", "amount", "maxTimeoutSeconds"},
        "UNSUPPORTED_TELEGRAPH_PAYMENT_QUOTE",
    )
    if quote != {
        "scheme": TELEGRAPH_SCHEME,
        "network": TELEGRAPH_NETWORK,
        "asset": TELEGRAPH_ASSET,
        "payTo": TELEGRAPH_PAY_TO,
        "amount": TELEGRAPH_AMOUNT,
        "maxTimeoutSeconds": 60,
    }:
        raise BindingError("UNSUPPORTED_TELEGRAPH_PAYMENT_QUOTE")
    return quote


def _receipt(receipt: Any, receipt_header: str, request_hash: str,
             response_hash: str, transfer: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(receipt, dict):
        raise BindingError("MALFORMED_TELEGRAPH_RECEIPT")
    try:
        header_obj = json.loads(
            receipt_header,
            object_pairs_hook=_no_duplicate_pairs,
            parse_constant=_reject_constant,
        )
    except (TypeError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise BindingError("MALFORMED_TELEGRAPH_RECEIPT_HEADER") from exc
    if not isinstance(header_obj, dict) or digest(header_obj) != digest(receipt):
        raise BindingError("RECEIPT_HEADER_OBJECT_MISMATCH")
    required = {"intent", "amount", "network", "asset", "payTo", "tx_hash",
                "receipt_hash", "job_id", "request_sha256", "response_sha256"}
    if not required.issubset(receipt):
        raise BindingError("RECEIPT_MISSING_BINDING_FIELDS")
    if receipt["intent"] != TELEGRAPH_INTENT or receipt["amount"] != TELEGRAPH_AMOUNT:
        raise BindingError("TELEGRAPH_RECEIPT_PAYMENT_MISMATCH")
    if receipt["network"] != TELEGRAPH_NETWORK or receipt["asset"] != TELEGRAPH_ASSET:
        raise BindingError("TELEGRAPH_RECEIPT_NETWORK_OR_ASSET_MISMATCH")
    if receipt["payTo"].lower() != TELEGRAPH_PAY_TO.lower():
        raise BindingError("TELEGRAPH_RECEIPT_RECIPIENT_MISMATCH")
    if TX_HASH.fullmatch(receipt["tx_hash"]) is None:
        raise BindingError("INVALID_TELEGRAPH_TRANSACTION_HASH")
    if not isinstance(receipt["receipt_hash"], str) or not TX_HASH.fullmatch(receipt["receipt_hash"]):
        raise BindingError("INVALID_TELEGRAPH_RECEIPT_HASH")
    _job_id(receipt["job_id"])
    _hash_field(receipt, "request_sha256", request_hash, "RECEIPT_REQUEST_DIGEST_MISMATCH")
    _hash_field(receipt, "response_sha256", response_hash, "RECEIPT_RESPONSE_DIGEST_MISMATCH")
    expected_transfer = {
        "chain_id": TELEGRAPH_CHAIN_ID,
        "tx_hash": receipt["tx_hash"],
        "status": "0x1",
        "token": TELEGRAPH_ASSET,
        "from": transfer.get("from"),
        "to": TELEGRAPH_PAY_TO,
        "amount": TELEGRAPH_AMOUNT,
    }
    if transfer != expected_transfer:
        raise BindingError("INDEPENDENT_TRANSFER_DOES_NOT_MATCH_RECEIPT")
    _address(transfer["from"], "payment_payer")
    return receipt


def _history(history: Any, acp: dict[str, Any], requirement_raw: bytes) -> dict[str, Any]:
    if not isinstance(history, dict):
        raise BindingError("MALFORMED_ACP_HISTORY")
    if history.get("protocol") != "v2" or history.get("status") != "funded":
        raise BindingError("ACP_HISTORY_NOT_FUNDED_V2")
    if history.get("chainId") != acp["chain_id"] or history.get("jobId") != acp["job_id"]:
        raise BindingError("ACP_HISTORY_JOB_ID_MISMATCH")
    entries = history.get("entries")
    if (not isinstance(entries, list) or history.get("entryCount") != len(entries)
            or len(entries) > 1000):
        raise BindingError("INVALID_ACP_HISTORY_ENTRIES")
    requirement_entries = []
    system_events = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise BindingError("INVALID_ACP_HISTORY_ENTRY")
        if entry.get("kind") == "message" and entry.get("contentType") == "requirement":
            requirement_entries.append(entry)
        elif entry.get("kind") == "system":
            event = entry.get("event")
            if isinstance(event, dict) and isinstance(event.get("type"), str):
                system_events.append(event["type"])
    if len(requirement_entries) != 1:
        raise BindingError("ACP_REQUIREMENT_NOT_UNIQUE")
    if system_events[:3] != ["job.created", "budget.set", "job.funded"]:
        raise BindingError("ACP_LIFECYCLE_NOT_FUNDED_IN_ORDER")
    entry = requirement_entries[0]
    if entry.get("from", "").lower() != acp["buyer"].lower():
        raise BindingError("ACP_REQUIREMENT_BUYER_MISMATCH")
    if not isinstance(entry.get("content"), str) or entry["content"].encode("utf-8") != requirement_raw:
        raise BindingError("ACP_REQUIREMENT_BYTES_NOT_IN_HISTORY")
    return history


def _verify(manifest: dict[str, Any]) -> dict[str, Any]:
    expected_top = {"schema", "classification", "telegraph", "acp", "delivery"}
    _exact_fields(manifest, expected_top, "INVALID_BINDING_MANIFEST")
    if manifest["schema"] != SCHEMA or manifest["classification"] not in CLASSIFICATIONS:
        raise BindingError("INVALID_BINDING_MANIFEST")
    telegraph = _exact_fields(
        manifest["telegraph"],
        {"request_url", "request_body_b64", "request_sha256", "quote",
         "payment_response_header", "receipt_header", "receipt",
         "response_body_b64", "response_sha256", "payment_transfer"},
        "INVALID_TELEGRAPH_EVIDENCE",
    )
    acp = _exact_fields(
        manifest["acp"],
        {"chain_id", "job_id", "buyer", "provider", "requirement_body_b64",
         "requirement_sha256", "history_body_b64", "history_sha256"},
        "INVALID_ACP_EVIDENCE",
    )
    delivery_meta = _exact_fields(
        manifest["delivery"],
        {"body_b64", "sha256"},
        "INVALID_DELIVERY_EVIDENCE",
    )
    if telegraph["request_url"] != TELEGRAPH_URL:
        raise BindingError("TELEGRAPH_REQUEST_URL_MISMATCH")
    _quote(telegraph["quote"])
    if not isinstance(telegraph["payment_response_header"], str) or not telegraph["payment_response_header"].strip():
        raise BindingError("MISSING_PAYMENT_RESPONSE_HEADER")
    request_raw, request = _json_bytes(telegraph["request_body_b64"], "telegraph_request")
    if bytes_digest(request_raw) != telegraph["request_sha256"]:
        raise BindingError("TELEGRAPH_REQUEST_DIGEST_MISMATCH")
    if request_raw != ANCHOR_REQUEST_BYTES or request != ANCHOR_REQUEST:
        raise BindingError("TELEGRAPH_REQUEST_TARGET_MISMATCH")
    response_raw, response = _json_bytes(telegraph["response_body_b64"], "telegraph_response")
    if bytes_digest(response_raw) != telegraph["response_sha256"]:
        raise BindingError("TELEGRAPH_RESPONSE_DIGEST_MISMATCH")
    if not isinstance(response, dict) or not isinstance(response.get("report_job"), dict):
        raise BindingError("MISSING_ORIGINAL_REPORT_JOB_ID")
    report_job = _report_job(response["report_job"])
    receipt = _receipt(
        telegraph["receipt"], telegraph["receipt_header"],
        telegraph["request_sha256"], telegraph["response_sha256"],
        telegraph["payment_transfer"],
    )
    if receipt["job_id"] != report_job["job_id"]:
        raise BindingError("TELEGRAPH_REPORT_JOB_RECEIPT_MISMATCH")
    if not (type(acp["chain_id"]) is int and acp["chain_id"] == ACP_CHAIN_ID):
        raise BindingError("ACP_CHAIN_MISMATCH")
    _job_id(acp["job_id"], "INVALID_ACP_JOB_ID")
    buyer = _address(acp["buyer"], "ACP_BUYER")
    provider_wallet = _address(acp["provider"], "ACP_PROVIDER")
    if buyer.lower() == provider_wallet.lower():
        raise BindingError("ACP_BUYER_PROVIDER_NOT_DISTINCT")
    if provider_wallet.lower() != FALSUM_PROVIDER_WALLET.lower():
        raise BindingError("ACP_PROVIDER_MISMATCH")
    requirement_raw, requirement = _json_bytes(acp["requirement_body_b64"], "acp_requirement")
    if bytes_digest(requirement_raw) != acp["requirement_sha256"]:
        raise BindingError("ACP_REQUIREMENT_DIGEST_MISMATCH")
    history_raw, history = _json_bytes(acp["history_body_b64"], "acp_history")
    if bytes_digest(history_raw) != acp["history_sha256"]:
        raise BindingError("ACP_HISTORY_DIGEST_MISMATCH")
    _history(history, acp, requirement_raw)
    requirement = _exact_fields(
        requirement,
        {"schema", "offering", "report_job", "report", "telegraph_binding"},
        "REPORT_JOB_SCHEMA_LIMITATION",
    )
    if requirement["schema"] != REQUEST_SCHEMA_V2 or requirement["offering"] != OFFERING:
        raise BindingError("REPORT_JOB_SCHEMA_LIMITATION")
    if digest(requirement["report_job"]) != digest(report_job):
        raise BindingError("ACP_ORIGINAL_REPORT_JOB_MISMATCH")
    report = _exact_fields(requirement["report"], provider.V2_REPORT_FIELDS, "INVALID_ACP_REPORT")
    if (report["schema"] != REPORT_SCHEMA_V2 or report["chain_id"] != report_job["chain_id"]
            or report["job_id"] != report_job["job_id"] or report["target"] != report_job["target"]):
        raise BindingError("ACP_REPORT_ORIGINAL_JOB_MISMATCH")
    _hash_field(report, "source_response_sha256", telegraph["response_sha256"],
                "EVALUATED_REPORT_SOURCE_RESPONSE_MISMATCH")
    if report["receipt_hash"] != receipt["receipt_hash"]:
        raise BindingError("ACP_REPORT_RECEIPT_MISMATCH")
    binding_ref = _exact_fields(
        requirement["telegraph_binding"],
        BINDING_REF_FIELDS,
        "REPORT_JOB_SCHEMA_LIMITATION",
    )
    if binding_ref["schema"] != BINDING_REF_SCHEMA:
        raise BindingError("REPORT_JOB_SCHEMA_LIMITATION")
    expected_ref = {
        "schema": BINDING_REF_SCHEMA,
        "request_sha256": telegraph["request_sha256"],
        "response_sha256": telegraph["response_sha256"],
        "receipt_hash": receipt["receipt_hash"],
        "tx_hash": receipt["tx_hash"],
        "report_job_digest": digest(report_job),
        "report_digest": digest(report),
    }
    if binding_ref != expected_ref:
        raise BindingError("TELEGRAPH_ACP_BINDING_REFERENCE_MISMATCH")
    delivery_raw, delivery = _json_bytes(delivery_meta["body_b64"], "acp_delivery")
    if bytes_digest(delivery_raw) != delivery_meta["sha256"]:
        raise BindingError("ACP_DELIVERY_DIGEST_MISMATCH")
    if not isinstance(delivery, dict) or delivery.get("schema") != RESULT_SCHEMA:
        raise BindingError("INVALID_FALSUM_DELIVERY")
    if delivery.get("offering") != OFFERING or delivery.get("verification_job") != {
        "chain_id": acp["chain_id"], "job_id": acp["job_id"]
    }:
        raise BindingError("ACP_DELIVERY_JOB_MISMATCH")
    if delivery.get("requirement_digest") != digest(requirement):
        raise BindingError("ACP_DELIVERY_REQUIREMENT_MISMATCH")
    if delivery.get("history_digest") != digest(history):
        raise BindingError("ACP_DELIVERY_HISTORY_MISMATCH")
    if delivery.get("telegraph_binding") != expected_ref:
        raise BindingError("FALSUM_DELIVERY_BINDING_MISMATCH")
    evaluation = delivery.get("report_evaluation")
    gate_report = dict(report)
    del gate_report["source_response_sha256"]
    gate_report["schema"] = gate.SCHEMA
    if (not isinstance(evaluation, dict)
            or evaluation.get("job_digest") != digest(report_job)
            or evaluation.get("deliverable_digest") != digest(gate_report)
            or evaluation.get("source_response_sha256") != telegraph["response_sha256"]
            or evaluation.get("evaluated_report_digest") != digest(report)):
        raise BindingError("FALSUM_EVALUATION_BINDING_MISMATCH")
    return {
        "schema": SCHEMA,
        "decision": "BOUND",
        "reasons": ["EXACT_TELEGRAPH_REQUEST_RESPONSE_RECEIPT_AND_ACP_JOB_BOUND"],
        "evidence_classification": manifest["classification"],
        "telegraph_request_sha256": telegraph["request_sha256"],
        "telegraph_response_sha256": telegraph["response_sha256"],
        "telegraph_receipt_hash": receipt["receipt_hash"],
        "telegraph_transaction_hash": receipt["tx_hash"],
        "original_report_job": {
            "chain_id": report_job["chain_id"],
            "job_id": report_job["job_id"],
            "digest": digest(report_job),
        },
        "acp_job": {"chain_id": acp["chain_id"], "job_id": acp["job_id"]},
        "binding_verified": True,
        "independent_customer_adoption": False,
        "adoption_status": "NOT_ESTABLISHED_BY_THIS_VERIFIER",
        "telegraph_binding": expected_ref,
        "trusted_custody": {
            "status": "CALLER_VERIFIED",
            "job_digest": digest(report_job),
            "response_digest": digest({k: v for k, v in report["response"].items()}),
            "receipt_hash": receipt["receipt_hash"],
            "intent": TELEGRAPH_INTENT,
        },
        "purchase_authorized": False,
        "automatic_settlement_authorized": False,
    }


def verify(manifest: Any) -> dict[str, Any]:
    """Return BOUND or HOLD without ever synthesizing a job or custody claim."""
    try:
        return _verify(manifest)
    except (BindingError, TypeError, KeyError, AttributeError, UnicodeError, ValueError) as exc:
        reason = exc.reason if isinstance(exc, BindingError) else "INVALID_BINDING_MANIFEST"
        classification = manifest.get("classification") if isinstance(manifest, dict) else None
        if classification not in CLASSIFICATIONS:
            classification = "UNKNOWN"
        return {
            "schema": SCHEMA,
            "decision": "HOLD",
            "reasons": [reason],
            "evidence_classification": classification,
            "binding_verified": False,
            "independent_customer_adoption": False,
            "adoption_status": "NOT_ESTABLISHED_BY_THIS_VERIFIER",
            "purchase_authorized": False,
            "automatic_settlement_authorized": False,
        }


def _load(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > 4_000_000:
        raise ValueError("manifest too large")
    return json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(verify(_load(args.manifest)), sort_keys=True, allow_nan=False))


if __name__ == "__main__":
    main()
