"""Phase 3L: private Anjoman evaluation-pool preflight and unsigned handoff.

This module NEVER uploads evaluation material, uses an Ethereum key,
contacts a network, publishes question/answer content or asserts acceptance.
Source material and review attestations remain *local to the operator*.

Protocol source: https://anjoman.ai/docs/scoring/contribute-evaluation-data
Target bounty: telegraphprotocol/bounties#96, SECURITY_REVIEW_GENERAL.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import unicodedata
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlsplit

INTENT = "SECURITY_REVIEW_GENERAL"
CHAIN_ID = 11155111  # Sepolia default, not inferred from a user account
STATUS = "PHASE3L_PRIVATE_PREFLIGHT_ONLY_NOT_ACCEPTED_OR_INDEPENDENTLY_VERIFIED"
MAX_BODY = 32 * 1024 * 1024
MAX_ROW = 64 * 1024
MAX_ROWS = 5000
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
NONCE = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
ALLOWED = {"prompt", "chosen", "rejected", "label_kind", "intent_id", "provenance"}
DISALLOWED_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "ghp_", "github_pat_",
)


class EvalpoolError(ValueError):
    """The operator's unpublished material is unsafe or not yet reviewed."""


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normal(text: str) -> str:
    return " ".join(unicodedata.normalize("NFC", text).split())


def _no_private_content(text: str, field: str) -> None:
    if any(unicodedata.category(c) == "Cc" for c in text):
        raise EvalpoolError(f"{field}: control characters are not allowed")
    if any(marker in text for marker in DISALLOWED_MARKERS):
        raise EvalpoolError(f"{field}: possible secret-bearing material is forbidden")


def _url(source: str) -> None:
    try:
        u = urlsplit(source)
        host = (u.hostname or "").casefold()
        _ = u.port
    except ValueError as exc:
        raise EvalpoolError("invalid provenance.source_url") from exc
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if (u.scheme != "https" or not host or u.username or u.password
            or (ip is not None and not ip.is_global)
            or host in ("localhost", "metadata.google.internal")
            or host.endswith((".local", ".internal", ".localhost"))
            or any(c.isspace() for c in source)):
        raise EvalpoolError("provenance.source_url must be a public HTTPS reference without credentials")
    # Network source reachability/content correctness still needs human checking.


def _read_private(path: Path) -> bytes:
    if not path.is_file() or path.is_symlink():
        raise EvalpoolError("a regular, non-symlink local private file is required")
    if path.stat().st_size > MAX_BODY:
        raise EvalpoolError("evaluation body exceeds 32 MiB")
    body = path.read_bytes()
    if not body or not body.endswith(b"\n") or b"\r" in body:
        raise EvalpoolError("private JSONL must be nonempty UTF-8 LF records ending with newline")
    return body


def validate_rows(body: bytes, *, allow_unverified_ai: bool = False) -> tuple[list[dict], list[str]]:
    """Strict local heuristic, NOT the node's curator or semantic accuracy test."""
    if not isinstance(body, bytes) or not body or len(body) > MAX_BODY:
        raise EvalpoolError("body missing or over the 32 MiB node limit")
    if not body.endswith(b"\n") or b"\r" in body:
        raise EvalpoolError("JSONL must end with LF and contain no CR")
    lines = body.splitlines(keepends=True)
    if len(lines) > MAX_ROWS:
        raise EvalpoolError("conservative 5000-row daily contributor cap exceeded")
    rows, hashes, seen_prompts, seen_rejected, source_kinds = [], [], [], set(), set()
    for n, line in enumerate(lines, 1):
        if len(line) > MAX_ROW:
            raise EvalpoolError(f"row {n}: exceeds 64 KiB")
        try:
            item = json.loads(line.decode("utf-8", errors="strict"))
        except (UnicodeError, ValueError) as exc:
            raise EvalpoolError(f"row {n}: invalid UTF-8 JSON") from exc
        if not isinstance(item, dict) or set(item) - ALLOWED:
            raise EvalpoolError(f"row {n}: unknown fields or nonobject")
        if item.get("intent_id") != INTENT or item.get("label_kind") != "preference_pair":
            raise EvalpoolError(f"row {n}: explicit exact Intent and preference_pair required")
        data = {}
        for key, low, high in (("prompt", 16, 16000), ("chosen", 8, 32000), ("rejected", 8, 32000)):
            value = item.get(key)
            if not isinstance(value, str):
                raise EvalpoolError(f"row {n}: missing {key}")
            _no_private_content(value, key)
            cleaned = _normal(value)
            if not low <= len(cleaned) <= high:
                raise EvalpoolError(f"row {n}: {key} exceeds node limits")
            data[key] = cleaned
        if data["chosen"] == data["rejected"]:
            raise EvalpoolError(f"row {n}: identical answer content")
        a, b = len(data["chosen"].split()), len(data["rejected"].split())
        if min(a, b) < 3 or not 0.70 <= a / b <= 1.43:
            raise EvalpoolError(f"row {n}: implausibly unbalanced or trivial answers")
        if data["rejected"] in seen_rejected:
            raise EvalpoolError(f"row {n}: reused worse answer")
        seen_rejected.add(data["rejected"])
        key = data["prompt"].casefold()
        if any(SequenceMatcher(a=key, b=old).ratio() >= 0.85 for old in seen_prompts):
            raise EvalpoolError(f"row {n}: duplicate or 85%-similar prompt (local heuristic)")
        seen_prompts.append(key)
        prov = item.get("provenance")
        if (not isinstance(prov, dict) or set(prov) != {"source_kind", "source_url"}
                or not isinstance(prov.get("source_url"), str)):
            raise EvalpoolError(f"row {n}: complete provenance.source_kind/source_url required")
        kind = prov.get("source_kind")
        if kind != "human" and not (allow_unverified_ai and kind in ("llm", "synthetic", "generated", "model")):
            raise EvalpoolError(f"row {n}: unverified AI provenance requires explicit --allow-unverified-ai")
        source_kinds.add(kind)
        if "human" in source_kinds and len(source_kinds) > 1:
            raise EvalpoolError("do not mix claimed human and unverified AI rows in one handoff")
        _url(prov["source_url"])
        rows.append(item)
        hashes.append(_hash(line.rstrip(b"\n")))
    return rows, hashes


def make_review_index(rows: list[dict], hashes: list[str]) -> dict:
    return {
        "schema_version": 1,
        "status": STATUS,
        "intent_id": INTENT,
        "rows": [{"row_number": i+1, "row_sha256": h}
                 for i, h in enumerate(hashes)],
        "note": "SHA256 of each exact UTF-8 JSONL line without its LF, not source validation or human expertise."
    }


def check_attestations(attestations: object, hashes: list[str]) -> dict:
    """Checks local statement shape and row binding; DOES NOT authenticate reviewer identity."""
    if (not isinstance(attestations, dict)
            or set(attestations) != {"schema_version", "intent_id", "attestations"}
            or type(attestations["schema_version"]) is not int
            or attestations["schema_version"] != 1
            or attestations["intent_id"] != INTENT
            or not isinstance(attestations["attestations"], list)
            or len(attestations["attestations"]) != len(hashes)):
        raise EvalpoolError("a local, per-row review-attestation file is required")
    for i, (claim, expected) in enumerate(zip(attestations["attestations"], hashes), 1):
        if (not isinstance(claim, dict)
                or set(claim) != {"row_sha256", "reviewer_id", "source_and_patch_checked",
                                  "chosen_supported", "rejected_incorrect", "conflicts_resolved"}
                or claim.get("row_sha256") != expected
                or not isinstance(claim.get("reviewer_id"), str)
                or not 3 <= len(claim["reviewer_id"].strip()) <= 128
                or any(claim.get(flag) is not True for flag in
                       ("source_and_patch_checked", "chosen_supported",
                        "rejected_incorrect", "conflicts_resolved"))):
            raise EvalpoolError(f"row {i}: missing, stale or uncompleted human review statement")
    return {
        "submitted_review_statements": len(hashes),
        "reviewer_identity_authenticated": False,
        "independent_expertise_verified": False,
        "material_accuracy_certified": False,
    }


def sign_message(body: bytes, nonce: str, chain_id: int) -> str:
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise EvalpoolError("nonce must have 8..128 safe characters")
    if type(chain_id) is not int or chain_id <= 0:
        raise EvalpoolError("chain ID must be an explicit positive integer")
    return (f"Telegraph eval-pool submission v1\n"
            f"intent_id: {INTENT}\n"
            f"body_sha256: {_hash(body)}\n"
            f"nonce: {nonce}\n"
            f"chain_id: {chain_id}")


def build(files: Path, review_path: Path | None, output_dir: Path,
          address: str, nonce: str, chain_id: int, *, allow_unverified_ai: bool = False) -> dict:
    if not isinstance(address, str) or not ADDRESS.fullmatch(address):
        raise EvalpoolError("contributor address must be an Ethereum 0x/40-hex address")
    body = _read_private(files)
    rows, row_hashes = validate_rows(body, allow_unverified_ai=allow_unverified_ai)
    kinds = {r["provenance"]["source_kind"] for r in rows}
    ai_only = "human" not in kinds
    if ai_only:
        if review_path is not None:
            raise EvalpoolError("do not attach human verification statements to unverified AI draft handoff")
        review = {"submitted_review_statements": 0, "reviewer_identity_authenticated": False,
                  "independent_expertise_verified": False, "material_accuracy_certified": False}
    else:
        if review_path is None or not review_path.is_file() or review_path.is_symlink():
            raise EvalpoolError("human-origin submission requires a local non-symlink review file")
        attestations = json.loads(review_path.read_text(encoding="utf-8"))
        review = check_attestations(attestations, row_hashes)
    message = sign_message(body, nonce, chain_id)
    if output_dir.is_symlink() or output_dir.exists():
        raise EvalpoolError("choose a new private output directory; no overwriting")
    if files.resolve().is_relative_to(output_dir.resolve()) or (review_path is not None and review_path.resolve().is_relative_to(output_dir.resolve())):
        raise EvalpoolError("source and output must not overlap")
    summary = {
        "schema_version": 1, "status": STATUS, "intent_id": INTENT,
        "body_sha256": _hash(body), "body_bytes": len(body), "row_count": len(rows),
        "review_statement_check": review,
        "origin_declarations": sorted(kinds),
        "provenance_class": "unverified" if ai_only else "attested_if_source_url_is_valid",
        "operator_review_required_before_optional_upload": True,
        "contributor_address": address, "chain_id": chain_id,
        "signed": False, "uploaded": False, "network_received": 0,
        "network_admitted": 0, "network_eligible_rows": 0,
        "independent_expert_labels_verified": 0,
        "network_eligibility_checked": False,
        "notice": "Local syntax/source URL/review statement preflight only. Private row material remains unsubmitted. Human and network semantic review, EIP-191 signing, actual upload and eligibility checking are still required."
    }
    output_dir.mkdir(parents=True, mode=0o700)
    os.chmod(output_dir, 0o700)
    for name, raw in (
        ("PRIVATE-EVALPOOL-ROWS.jsonl", body),
        ("EIP191-MESSAGE-TO-SIGN.txt", message.encode("utf-8")),
        ("UNSIGNED-HANDOFF.json", (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8")),
    ):
        fd = os.open(output_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Never-submit private SECURITY_REVIEW_GENERAL preflight and EIP191 signing message")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("inspect", help="offline private row constraints only; stdout counts and hashes, no material")
    check.add_argument("--file", type=Path, required=True)
    check.add_argument("--allow-unverified-ai", action="store_true", help="explicitly accept honestly labeled AI draft provenance")
    index = sub.add_parser("review-index", help="write local row SHA index for a human reviewer")
    index.add_argument("--file", type=Path, required=True)
    index.add_argument("--allow-unverified-ai", action="store_true")
    index.add_argument("--out", type=Path, required=True)
    package = sub.add_parser("prepare", help="write unsigned, unsubmitted local handoff, never network")
    package.add_argument("--file", type=Path, required=True)
    package.add_argument("--review-attestations", type=Path)
    package.add_argument("--allow-unverified-ai", action="store_true")
    package.add_argument("--out-dir", type=Path, required=True)
    package.add_argument("--address", required=True)
    package.add_argument("--nonce")
    package.add_argument("--chain-id", type=int, default=CHAIN_ID)
    args = parser.parse_args(argv)
    try:
        if args.cmd in ("inspect", "review-index"):
            body = _read_private(args.file)
            rows, hashes = validate_rows(body, allow_unverified_ai=args.allow_unverified_ai)
            if args.cmd == "inspect":
                result = {"status": STATUS, "rows": len(rows), "body_sha256": _hash(body),
                          "provenance_source_kinds": sorted({r["provenance"]["source_kind"] for r in rows}),
                          "eligible": False, "human_accuracy_verified": False}
            else:
                if args.out.exists() or args.out.is_symlink() or args.out.resolve() == args.file.resolve():
                    raise EvalpoolError("review index cannot overwrite existing/source files")
                args.out.parent.mkdir(parents=True, exist_ok=True)
                result = make_review_index(rows, hashes)
                args.out.write_text(json.dumps(result, indent=2) + "\n")
                result = {"status": STATUS, "rows": len(rows), "review_index_written": True}
        else:
            result = build(args.file, args.review_attestations, args.out_dir, args.address,
                           args.nonce or secrets.token_hex(16), args.chain_id,
                           allow_unverified_ai=args.allow_unverified_ai)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (EvalpoolError, OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"FALSUM 3L PRIVATE EVALPOOL PREFLIGHT FAILED: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
