"""Verify pinned OSV-format advisories with conservative, fail-closed version checks.

A version verdict describes *one OSV advisory*, not exploitability or safety.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

try:
    from packaging.version import InvalidVersion, Version
except ImportError:  # pragma: no cover - packaging is a declared runtime dependency
    InvalidVersion = None
    Version = None

ADVISORY = re.compile(r"^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$", re.I)
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
STABLE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
GHSA_SOURCE = re.compile(r"^https://raw\.githubusercontent\.com/github/advisory-database/([a-f0-9]{40})/advisories/github-reviewed/(\d{4})/(\d{2})/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})/\4\.json$", re.I)
MAX_BYTES = 3_000_000


class SourceError(ValueError):
    """An advisory cannot be verified or its version is undecidable."""


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
                    raise SourceError('invalid prerelease leading zero')
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


def _stable_cmp(a: str, b: str) -> int:
    """Backward-compatible name for the strict npm SemVer comparator.

    Older callers imported this private helper while the resolver intentionally
    supported only stable triples.  New decisions use the ecosystem-native
    comparator below; retaining this function avoids silently changing those
    callers while removing the old PyPI/npm conflation from ``version_status``.
    """
    return _cmp(a, b)


def _pypi(value: str):
    if Version is None:
        raise SourceError('packaging is required for PyPI version semantics')
    try:
        return Version(value)
    except (InvalidVersion, TypeError) as exc:
        raise SourceError(f'unsupported PEP 440 version: {value!r}') from exc


def _pypi_cmp(a: str, b: str) -> int:
    left, right = _pypi(a), _pypi(b)
    return (left > right) - (left < right)


def _event_intervals(item: dict, comparator):
    """Parse one OSV event stream into a validated union of intervals.

    A malformed event invalidates the whole range.  In particular, numeric
    ``limit`` values are not treated as ``fixed`` bounds, and a valid interval
    cannot hide a later malformed interval in the same event stream.
    """
    events = item.get('events')
    if not isinstance(events, list) or not events:
        raise SourceError('missing OSV range events')
    intervals = []
    opened = None
    previous_end = None
    previous_kind = None
    terminated_unbounded = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise SourceError('invalid OSV event')
        kind, bound = next(iter(event.items()))
        if kind not in ('introduced', 'fixed', 'last_affected', 'limit') or not isinstance(bound, str):
            raise SourceError('unsupported OSV event')
        if kind == 'introduced':
            if opened is not None or terminated_unbounded:
                raise SourceError('overlapping or unterminated OSV range')
            if bound != '0':
                comparator(bound, bound)
                if previous_end is not None:
                    relation = comparator(bound, previous_end)
                    if relation < 0 or (relation == 0 and previous_kind == 'last_affected'):
                        raise SourceError('overlapping or unordered OSV range')
            elif previous_end is not None:
                raise SourceError('unbounded OSV range follows a closed range')
            opened = bound
            continue
        if opened is None:
            raise SourceError('OSV closing event without introduced')
        if kind == 'limit':
            if bound != '*':
                raise SourceError('numeric OSV limit is unsupported')
            intervals.append((opened, None, 'limit'))
            opened = None
            terminated_unbounded = True
            continue
        comparator(bound, bound)
        if opened != '0' and comparator(opened, bound) > 0:
            raise SourceError('reversed OSV range')
        intervals.append((opened, bound, kind))
        previous_end, previous_kind = bound, kind
        opened = None
    if opened is not None:
        intervals.append((opened, None, None))
    if not intervals:
        raise SourceError('OSV range contains no interval')
    return intervals


def _in_events(version: str, item: dict, comparator) -> bool:
    matched = False
    for start, end, kind in _event_intervals(item, comparator):
        left = start == '0' or comparator(version, start) >= 0
        right = end is None or (
            comparator(version, end) <= 0 if kind == 'last_affected' else comparator(version, end) < 0
        )
        matched = matched or (left and right)
    return matched


def _in_semver_range(version: str, item: dict) -> bool:
    return _in_events(version, item, _cmp)


def matches_id(record: dict, advisory_id: str) -> bool:
    return advisory_id.upper() in {str(x).upper() for x in [record.get('id'), *(record.get('aliases') or [])]}


def parse_osv(raw: bytes, advisory_id: str) -> dict:
    if not ADVISORY.fullmatch(advisory_id):
        raise SourceError('only CVE/GHSA IDs supported')
    if not raw or len(raw) > MAX_BYTES:
        raise SourceError('empty or oversized advisory')
    try:
        record = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise SourceError('invalid advisory JSON') from e
    if not isinstance(record, dict) or not isinstance(record.get('affected'), list):
        raise SourceError('OSV record missing affected list')
    if record.get('withdrawn'):
        raise SourceError('OSV entry withdrawn; cannot issue a verdict')
    if not matches_id(record, advisory_id):
        raise SourceError('requested advisory ID missing from record and aliases')
    return record


def version_status(record: dict, ecosystem: str, package: str, version: str) -> str:
    """Return affected/unaffected/unknown for one advisory, never for the deployment.

    ECOSYSTEM ranges use strict SemVer for npm and PEP 440 for PyPI.  Exact
    enumerated versions may establish ``affected`` for other formats, but a
    missing version never establishes ``unaffected`` without complete range
    support.
    """
    if not all(isinstance(x, str) and x for x in (ecosystem, package, version)):
        raise SourceError('ecosystem/package/version required')
    if not isinstance(record, dict) or not isinstance(record.get('affected'), list):
        return 'unknown'
    found, undecidable, complete, affected_positive = False, False, False, False
    for affected in record.get('affected', []):
        if not isinstance(affected, dict):
            return 'unknown'
        pkg = affected.get('package') or {}
        if not isinstance(pkg, dict):
            return 'unknown'
        if pkg.get('ecosystem', '').casefold() != ecosystem.casefold() or pkg.get('name', '').casefold() != package.casefold():
            continue
        found = True
        versions = affected.get('versions', [])
        if not isinstance(versions, list):
            undecidable = True
        elif version in versions:
            affected_positive = True
        ranges = affected.get('ranges') or []
        if not ranges:
            undecidable = True
        for item in ranges:
            if not isinstance(item, dict):
                undecidable = True
                continue
            kind = item.get('type')
            if kind == 'SEMVER':
                try:
                    _semver(version)
                    matched = _in_events(version, item, _cmp)
                except SourceError:
                    undecidable = True
                    continue
            elif kind == 'ECOSYSTEM' and ecosystem.casefold() == 'npm':
                try:
                    _semver(version)
                    matched = _in_events(version, item, _cmp)
                except SourceError:
                    undecidable = True
                    continue
            elif kind == 'ECOSYSTEM' and ecosystem.casefold() == 'pypi':
                try:
                    _pypi(version)
                    matched = _in_events(version, item, _pypi_cmp)
                except SourceError:
                    undecidable = True
                    continue
            else:
                undecidable = True
                continue
            complete = True
            if matched:
                affected_positive = True
    if affected_positive:
        return 'affected'
    if not found or undecidable or not complete:
        return 'unknown'
    return 'unaffected'


def verify_snapshot(path: Path, advisory_id: str) -> tuple[dict, dict]:
    path = Path(path)
    meta_path = path.with_name(path.stem + '.meta.json')
    try:
        raw = path.read_bytes()
        meta = json.loads(meta_path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as e:
        raise SourceError('snapshot or metadata missing/invalid') from e
    if not isinstance(meta, dict):
        raise SourceError('invalid snapshot metadata')
    digest = hashlib.sha256(raw).hexdigest()
    if digest != meta.get('sha256') or len(raw) != meta.get('byte_size'):
        raise SourceError('snapshot digest or byte size mismatch')
    if str(meta.get('requested_id', '')).upper() != advisory_id.upper():
        raise SourceError('snapshot requested_id mismatch')
    url = meta.get('source_url')
    api_url = f'https://api.osv.dev/v1/vulns/{advisory_id}'
    github_match = GHSA_SOURCE.fullmatch(url) if isinstance(url, str) else None
    if url != api_url and not (github_match and github_match.group(4).lower() == advisory_id.lower()):
        raise SourceError('source URL is not an approved pinned OSV/GHSA address')
    record = parse_osv(raw, advisory_id)
    if meta.get('canonical_id') != record.get('id'):
        raise SourceError('canonical advisory ID differs from snapshot')
    return record, meta


def audit_ledger_snapshots(ledger: dict, directory: Path, *, include_drafts: bool = False) -> list[str]:
    """Verify source integrity and limited version status; not an expert review."""
    errors = []
    checked = 0
    for evidence in ledger.get('evidence', []):
        if not isinstance(evidence, dict) or (evidence.get('review_status') != 'reviewed' and not include_drafts):
            continue
        checked += 1
        key, advisory_id = evidence.get('id'), evidence.get('advisory_id', '')
        if not isinstance(advisory_id, str) or not ADVISORY.fullmatch(advisory_id):
            errors.append(f'{key}: invalid advisory ID')
            continue
        try:
            record, meta = verify_snapshot(Path(directory) / f'{advisory_id}.json', advisory_id)
            if meta['sha256'] != evidence.get('source_sha256'):
                raise SourceError('ledger SHA-256 differs from snapshot')
            if meta['source_url'] != evidence.get('source_url'):
                raise SourceError('ledger source URL differs from snapshot')
            status = version_status(record, evidence.get('ecosystem', ''), evidence.get('package', ''), evidence.get('version', ''))
            if status == 'unknown':
                raise SourceError('version status unknown; expert review required')
            if evidence.get('verdict') != status:
                raise SourceError(f'ledger verdict conflicts with supported OSV status ({status})')
            excerpt = evidence.get('source_excerpt', '')
            if not isinstance(excerpt, str) or excerpt.strip().casefold() not in ((record.get('summary') or '') + '\n' + (record.get('details') or '')).casefold():
                raise SourceError('excerpt not found in source summary/details')
        except (SourceError, OSError) as exc:
            errors.append(f'{key}: {exc}')
    if checked == 0:
        errors.append('no evidence records for requested audit scope')
    return errors
