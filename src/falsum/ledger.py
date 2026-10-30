"""Offline, fail-closed evidence and preference-data validation for FALSUM.

This module checks structure, provenance metadata, and common dataset shortcuts.
It does NOT establish that a cited advisory is authentic or that a claim is true.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

INTENT = "SECURITY_REVIEW_GENERAL"
FAMILY = "SECURITY_REVIEW"
SPLITS = frozenset({"train", "validation", "holdout"})
VERDICTS = frozenset({"affected", "unaffected", "conditional"})
STATES = frozenset({"draft", "reviewed"})
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADVISORY = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.I)
TOKENS = re.compile(r"[a-z0-9]+")


class LedgerError(ValueError):
    """Raised when a ledger fails the publication quality gate."""


def _str(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _reviewed(record: dict) -> bool:
    return bool(_str(record.get("reviewer")) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", _str(record.get("reviewed_on"))))


def _https_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        p = urlsplit(value)
        return p.scheme == "https" and bool(p.hostname) and p.username is None and p.password is None and "." in p.hostname
    except ValueError:
        return False


def _similarity(a: str, b: str) -> float:
    left, right = set(TOKENS.findall(a.casefold())), set(TOKENS.findall(b.casefold()))
    return len(left & right) / len(left | right) if left or right else 1.0


def validate_ledger(data: object) -> list[str]:
    """Return actionable errors; never quietly discard an invalid or duplicate row."""
    errors: list[str] = []
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return ["root: expected object with schema_version=1"]
    evidence = data.get("evidence")
    pairs = data.get("pairs")
    if not isinstance(evidence, list) or not isinstance(pairs, list):
        return ["root: evidence and pairs must both be arrays"]

    by_id: dict[str, dict] = {}
    for index, item in enumerate(evidence):
        tag = f"evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{tag}: expected object")
            continue
        key = _str(item.get("id"))
        if not key or key in by_id:
            errors.append(f"{tag}: missing or duplicate id")
        else:
            by_id[key] = item
        for field in ("ecosystem", "package", "version", "source_excerpt"):
            if not _str(item.get(field)):
                errors.append(f"{tag}: {field} is required")
        if not ADVISORY.fullmatch(_str(item.get("advisory_id"))):
            errors.append(f"{tag}: advisory_id must be CVE or GHSA identifier")
        if item.get("verdict") not in VERDICTS:
            errors.append(f"{tag}: invalid verdict")
        if not _https_url(item.get("source_url")):
            errors.append(f"{tag}: source_url must be a valid HTTPS URL")
        if item.get("review_status") not in STATES:
            errors.append(f"{tag}: invalid review_status")
        if item.get("review_status") == "reviewed":
            if not _reviewed(item):
                errors.append(f"{tag}: reviewed evidence needs reviewer and reviewed_on")
            if not SHA256.fullmatch(_str(item.get("source_sha256"))):
                errors.append(f"{tag}: reviewed evidence needs a 64-character source snapshot SHA-256")
            if _str(item.get("source_url")).endswith(".invalid"):
                errors.append(f"{tag}: placeholder URL cannot be reviewed evidence")

    seen_ids: set[str] = set()
    seen_negative: set[str] = set()
    seen_prompts: list[tuple[str, str]] = []
    used_advisories: dict[tuple[str, str, str], set[str]] = {}
    for index, item in enumerate(pairs):
        tag = f"pairs[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{tag}: expected object")
            continue
        key = _str(item.get("id"))
        if not key or key in seen_ids:
            errors.append(f"{tag}: missing or duplicate id")
        seen_ids.add(key)
        if item.get("intent_id") != INTENT:
            errors.append(f"{tag}: intent_id must be {INTENT}")
        split = item.get("split")
        if split not in SPLITS:
            errors.append(f"{tag}: split must be train, validation or holdout")
        if item.get("review_status") not in STATES:
            errors.append(f"{tag}: invalid review_status")
        prompt, chosen, rejected = (_str(item.get(x)) for x in ("prompt", "chosen", "rejected"))
        if min(len(prompt), len(chosen), len(rejected)) < 20:
            errors.append(f"{tag}: prompt and both answers must be at least 20 characters")
        if chosen.casefold() == rejected.casefold():
            errors.append(f"{tag}: chosen and rejected are identical")
        if chosen and rejected:
            ratio = len(chosen.split()) / max(len(rejected.split()), 1)
            if not 0.65 <= ratio <= 1.55:
                errors.append(f"{tag}: answer lengths are unbalanced (word ratio {ratio:.2f})")
            negative = hashlib.sha256(rejected.encode()).hexdigest()
            if negative in seen_negative:
                errors.append(f"{tag}: repeated rejected answer")
            seen_negative.add(negative)
        for other_id, other_prompt in seen_prompts:
            if prompt and _similarity(prompt, other_prompt) >= 0.85:
                errors.append(f"{tag}: prompt too similar to {other_id} (Jaccard >= 0.85)")
        if prompt:
            seen_prompts.append((key, prompt))
        evidence_ids = item.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids or len(evidence_ids) != len(set(map(str, evidence_ids))):
            errors.append(f"{tag}: evidence_ids must be a nonempty list of unique references")
            continue
        for evidence_id in evidence_ids:
            record = by_id.get(evidence_id) if isinstance(evidence_id, str) else None
            if record is None:
                errors.append(f"{tag}: unknown evidence id {evidence_id!r}")
                continue
            if item.get("review_status") == "reviewed" and record.get("review_status") != "reviewed":
                errors.append(f"{tag}: reviewed pair cites unreviewed evidence {evidence_id}")
            group = (_str(record.get("ecosystem")), _str(record.get("package")), _str(record.get("advisory_id")))
            if split in SPLITS:
                used_advisories.setdefault(group, set()).add(split)
        if item.get("review_status") == "reviewed" and not _reviewed(item):
            errors.append(f"{tag}: reviewed pair needs reviewer and reviewed_on")

    for group, splits in used_advisories.items():
        if len(splits) > 1:
            errors.append(f"dataset leakage: advisory {group} is shared across {sorted(splits)}")
    return errors


def load_ledger(path: str | Path) -> dict:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    errors = validate_ledger(data)
    if errors:
        raise LedgerError("\n".join(errors))
    return data


def export_pairs(data: dict, split: str) -> list[dict[str, str]]:
    """Produce the exact official training triplet without provenance metadata."""
    errors = validate_ledger(data)
    if errors:
        raise LedgerError("\n".join(errors))
    if split not in SPLITS:
        raise LedgerError(f"invalid split: {split}")
    rows = [p for p in data["pairs"] if p["split"] == split and p["review_status"] == "reviewed"]
    if not rows:
        raise LedgerError(f"no reviewed pairs in {split}; refusing empty export")
    return [{"prompt": p["prompt"], "chosen": p["chosen"], "rejected": p["rejected"]} for p in rows]


def export_jsonl(data: dict, split: str) -> str:
    return "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in export_pairs(data, split))
