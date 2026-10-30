"""Offline verification of pinned OSV JSON snapshots and conservative SemVer decisions.

OSV is a public vulnerability database, not proof of exploitability. Returning
'unaffected' means the queried version is outside every supported, complete
SemVer interval in this *one* record; it is not a security clearance.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ADVISORY = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.I)
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
MAX_BYTES = 3_000_000


class SourceError(ValueError):
    """An advisory snapshot cannot be trusted or its version cannot be decided."""


def _semver(value: str):
    match = SEMVER.fullmatch(value)
    if not match:
        raise SourceError(f"unsupported strict SemVer version: {value!r}")
    major, minor, patch, pre = match.groups()
    prerelease = []
    if pre is not None:
        for part in pre.split('.'):
            if part.isdigit():
                if len(part) > 1 and part[0] == '0':
                    raise SourceError("invalid prerelease leading zero")
                prerelease.append((0, int(part)))
            else:
                prerelease.append((1, part))
    return (int(major), int(minor), int(patch)), prerelease if pre is not None else None


def _cmp(a: str, b: str) -> int:
    acore, apre = _semver(a)
    bcore, bpre = _semver(b)
    if acore != bcore:
        return (acore > bcore) - (acore < bcore)
    if apre is None:
        return 0 if bpre is None else 1
    if bpre is None:
        return -1
    for left, right in zip(apre, bpre):
        if left != right:
            return (left > right) - (left < right)
    return (len(apre) > len(bpre)) - (len(apre) < len(bpre))


def _in_semver_range(version: str, item: dict) -> bool:
    """Interpret an OSV SEMVER event timeline, rejecting incomplete/invalid ones."""
    events = item.get('events')
    if not isinstance(events, list) or not events:
        raise SourceError("missing OSV range events")
    start = None
    previous = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise SourceError("invalid OSV event")
        kind, bound = next(iter(event.items()))
        if kind not in ('introduced', 'fixed', 'last_affected', 'limit') or not isinstance(bound, str):
            raise SourceError("unsupported OSV event")
        if kind == 'introduced':
            if start is not None or (bound != '0' and previous is not None and _cmp(bound, previous) < 0):
                raise SourceError("overlapping or unsorted OSV range")
            if bound != '0':
                _semver(bound)
            start = bound
            previous = bound if bound != '0' else previous
        else:
            if start is None:
                raise SourceError("OSV closing event without introduced")
            if bound == '*' and kind == 'limit':
                return _lower(version, start)
            _semver(bound)
            if start != '0' and _cmp(start, bound) > 0:
                raise SourceError("reversed OSV range")
            if _lower(version, start) and (_cmp(version, bound) <= 0 if kind == 'last_affected' else _cmp(version, bound) < 0):
                return True
            start = None
            previous = bound
    return bool(start is not None and _lower(version, start))


def _lower(version: str, bound: str) -> bool:
    return bound == '0' or _cmp(version, bound) >= 0


def matches_id(record: dict, advisory_id: str) -> bool:
    return advisory_id.upper() in {str(x).upper() for x in [record.get('id'), *(record.get('aliases') or [])]}


def parse_osv(raw: bytes, advisory_id: str) -> dict:
    if not ADVISORY.fullmatch(advisory_id):
        raise SourceError("only CVE/GHSA advisory IDs are supported")
    if not raw or len(raw) > MAX_BYTES:
        raise SourceError("empty or oversized advisory")
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SourceError("invalid advisory JSON") from e
    if not isinstance(record, dict) or not isinstance(record.get('affected'), list):
        raise SourceError("OSV record missing affected list")
    if record.get('withdrawn'):
        raise SourceError('OSV entry is withdrawn; no verdict can be issued')
    if not matches_id(record, advisory_id):
        raise SourceError("requested advisory ID absent from record id/aliases")
    return record


def version_status(record: dict, ecosystem: str, package: str, version: str) -> str:
    """Return affected/unaffected/unknown; never guess for ECOSYSTEM or GIT ranges."""
    if not all(isinstance(x, str) and x for x in (ecosystem, package, version)):
        raise SourceError("ecosystem/package/version required")
    try:
        _semver(version)
    except SourceError:
        return 'unknown'
    found = False
    undecidable = False
    complete = False
    for affected in record.get('affected', []):
        if not isinstance(affected, dict):
            return 'unknown'
        pkg = affected.get('package') or {}
        if not isinstance(pkg, dict):
            return 'unknown'
        if pkg.get('ecosystem', '').casefold() != ecosystem.casefold() or pkg.get('name', '').casefold() != package.casefold():
            continue
        found = True
        if version in affected.get('versions', []):
            return 'affected'
        ranges = affected.get('ranges') or []
        if not ranges:
            undecidable = True
        for item in ranges:
            if not isinstance(item, dict) or item.get('type') != 'SEMVER':
                undecidable = True
                continue
            try:
                if _in_semver_range(version, item):
                    return 'affected'
                complete = True
            except SourceError:
                undecidable = True
    if not found or undecidable or not complete:
        return 'unknown'
    return 'unaffected'


def verify_snapshot(path: Path, advisory_id: str) -> tuple[dict, dict]:
    """Check raw bytes against sibling .meta.json before using any claims."""
    path = Path(path)
    meta_path = path.with_name(path.stem + '.meta.json')
    try:
        raw = path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        raise SourceError("snapshot or metadata missing/invalid") from e
    if not isinstance(meta, dict):
        raise SourceError("invalid snapshot metadata")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != meta.get('sha256') or len(raw) != meta.get('byte_size'):
        raise SourceError("snapshot hash or byte size mismatch")
    if str(meta.get('requested_id', '')).upper() != advisory_id.upper():
        raise SourceError("snapshot requested_id mismatch")
    if meta.get('source_url') != f'https://api.osv.dev/v1/vulns/{advisory_id}':
        raise SourceError("snapshot not from the pinned OSV API address")
    return parse_osv(raw, advisory_id), meta


def audit_ledger_snapshots(ledger: dict, directory: Path) -> list[str]:
    """Conservative source-backed checks. Manual security review is still required."""
    errors: list[str] = []
    reviewed = [e for e in ledger.get('evidence', []) if isinstance(e, dict) and e.get('review_status') == 'reviewed']
    if not reviewed:
        return ['no reviewed evidence to audit']
    for evidence in reviewed:
        if not isinstance(evidence, dict) or evidence.get('review_status') != 'reviewed':
            continue
        key, advisory_id = evidence.get('id'), evidence.get('advisory_id', '')
        if not isinstance(advisory_id, str) or not ADVISORY.fullmatch(advisory_id):
            errors.append(f"{key}: invalid advisory ID")
            continue
        path = Path(directory) / f'{advisory_id}.json'
        try:
            record, meta = verify_snapshot(path, advisory_id)
            if meta['sha256'] != evidence.get('source_sha256'):
                raise SourceError("ledger SHA-256 differs from snapshot")
            if meta['source_url'] != evidence.get('source_url'):
                raise SourceError("ledger source URL differs from snapshot")
            status = version_status(record, evidence.get('ecosystem', ''), evidence.get('package', ''), evidence.get('version', ''))
            if status == 'unknown':
                raise SourceError("source cannot prove affected/unaffected version; independent review needed")
            if evidence.get('verdict') not in ('affected', 'unaffected') or evidence.get('verdict') != status:
                raise SourceError(f"ledger verdict conflicts with OSV version status ({status})")
            excerpt = evidence.get('source_excerpt', '')
            if not isinstance(excerpt, str) or excerpt.strip().casefold() not in ((record.get('summary') or '') + '\n' + (record.get('details') or '')).casefold():
                raise SourceError("source excerpt not found in OSV summary/details")
        except (SourceError, OSError) as exc:
            errors.append(f"{key}: {exc}")
    return errors
