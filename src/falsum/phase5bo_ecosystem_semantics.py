"""Phase 5BO: offline ecosystem-native version semantics.

Phase 5BN is intentionally unchanged.  This follow-up fixes the two observed
abstentions with PEP 440-aware and strict SemVer-aware candidate logic, retains
the exact registry responses used to establish version existence, exercises
disjoint intervals and unsupported ranges, and evaluates structured
claim/actions rather than mapping a reference label to an opaque token.

The committed audit is offline after snapshot capture.  Its external resolver
is a reference check, not human AppSec gold or independent adoption evidence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
from typing import Any
from urllib.request import Request, urlopen

from .phase5m_real_source_sensitive_model import ROOT


STATUS = "PHASE5BO_ECOSYSTEM_SEMANTICS_AUDIT"
FROZEN_STATUS = "PHASE5BO_ECOSYSTEM_SEMANTICS_FROZEN"
PROTOCOL = Path("data/phase5bo-ecosystem-semantics-protocol.json")
SNAPSHOT_ROOT = Path("data/phase5bo-registry-snapshots")
ADVISORY_COMMIT = "76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
ADVISORY_BASE = f"https://raw.githubusercontent.com/github/advisory-database/{ADVISORY_COMMIT}/"
PYPI_BASE = "https://pypi.org/pypi/"
NPM_BASE = "https://registry.npmjs.org/"
MAX_BYTES = 12_000_000
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "UNKNOWN_OR_INSUFFICIENT"
BLOCK_OR_UPGRADE = "BLOCK_OR_UPGRADE"
NO_ACTION_FOR_ADVISORY = "NO_ACTION_FOR_THIS_ADVISORY"
ABSTAIN_AND_REQUEST_EVIDENCE = "ABSTAIN_AND_REQUEST_EVIDENCE"
LAYOUT_SEED = 2026112702


class EcosystemSemanticsError(ValueError):
    """Raised when a snapshot, range or answer contract is invalid."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise EcosystemSemanticsError(message)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EcosystemSemanticsError("malformed JSON evidence") from exc


RECORDS = {
    "GHSA-98qm-wvgf-w4cf": {
        "ecosystem": "PyPI", "package": "pymongo", "month": "2026/10",
        "registry_url": "https://pypi.org/pypi/pymongo/json",
    },
    "GHSA-27x4-j476-jp5f": {
        "ecosystem": "PyPI", "package": "setuptools", "month": "2022/05",
        "registry_url": "https://pypi.org/pypi/setuptools/json",
    },
    "GHSA-jr5f-v2jv-69x6": {
        "ecosystem": "npm", "package": "axios", "month": "2025/03",
        "registry_url": "https://registry.npmjs.org/axios",
    },
    "GHSA-q2x7-8rv6-6q7h": {
        "ecosystem": "PyPI", "package": "jinja2", "month": "2024/12",
        "registry_url": "https://pypi.org/pypi/Jinja2/json",
    },
    "GHSA-66pp-5p9w-q87j": {
        "ecosystem": "npm", "package": "shescape", "month": "2025/03",
        "registry_url": "https://registry.npmjs.org/shescape",
    },
    "GHSA-x7hr-w5r2-h6wg": {
        "ecosystem": "npm", "package": "prismjs", "month": "2025/03",
        "registry_url": "https://registry.npmjs.org/prismjs",
    },
}

# The roster is fixed before labels are calculated.  The first two cases are
# regression cases for the Phase5BN abstentions; the other twelve are new.
SEED_CASES = (
    ("GHSA-98qm-wvgf-w4cf", "0.1pre"),
    ("GHSA-98qm-wvgf-w4cf", "3.9.0"),
    ("GHSA-27x4-j476-jp5f", "0.6c11"),
    ("GHSA-27x4-j476-jp5f", "0.7.2"),
    ("GHSA-jr5f-v2jv-69x6", "0.20.0-0"),
    ("GHSA-jr5f-v2jv-69x6", "0.30.0"),
    ("GHSA-jr5f-v2jv-69x6", "1.7.0-beta.0"),
    ("GHSA-jr5f-v2jv-69x6", "1.8.2"),
    ("GHSA-q2x7-8rv6-6q7h", "3.1.4"),
    ("GHSA-q2x7-8rv6-6q7h", "3.1.5"),
    ("GHSA-66pp-5p9w-q87j", "2.0.0-rc1"),
    ("GHSA-66pp-5p9w-q87j", "2.1.2"),
    ("GHSA-x7hr-w5r2-h6wg", "1.29.0"),
    ("GHSA-x7hr-w5r2-h6wg", "1.30.0"),
)

TOKEN_NAMES = ("claim-rhea", "claim-sable", "claim-umber")
SEMVER_RE = re.compile(
    r"^v?(?P<major>0|[1-9][0-9]*)(?:\.(?P<minor>0|[1-9][0-9]*))?"
    r"(?:\.(?P<patch>0|[1-9][0-9]*))?"
    r"(?:-(?P<pre>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+(?P<build>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _source_url(identifier: str) -> str:
    row = RECORDS[identifier]
    return f"{ADVISORY_BASE}advisories/github-reviewed/{row['month']}/{identifier}/{identifier}.json"


def _fetch(url: str) -> bytes:
    need(url.startswith(ADVISORY_BASE) or url.startswith(PYPI_BASE) or url.startswith(NPM_BASE),
         "unapproved source URL")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "FALSUM-phase5bo/1.0"})
    with urlopen(request, timeout=40) as response:
        need(response.status == 200 and response.geturl() == url, "source unavailable or redirected")
        raw = response.read(MAX_BYTES + 1)
    need(0 < len(raw) <= MAX_BYTES, "source exceeds byte cap")
    return raw


def _load_packaging() -> tuple[Any, Any, Any]:
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:
        raise EcosystemSemanticsError("install packaging==26.4") from exc
    return SpecifierSet, Version, InvalidVersion


def _node_path() -> str:
    value = os.environ.get("FALSUM_PHASE5BO_NODE_PATH")
    need(value, "FALSUM_PHASE5BO_NODE_PATH must point to semver@7.8.6 node_modules")
    probe = subprocess.run(
        ["node", "-e", "process.stdout.write(require('semver/package.json').version || '')"],
        text=True, capture_output=True, env={**os.environ, "NODE_PATH": value}, check=False,
    )
    need(probe.returncode == 0 and probe.stdout.strip().startswith("7."), "semver@7.x is unavailable")
    return value


def _parse_semver(value: object, *, partial: bool = False) -> tuple[tuple[int, int, int], tuple[tuple[int, object], ...] | None]:
    if not isinstance(value, str):
        raise EcosystemSemanticsError("SemVer is not a string")
    match = SEMVER_RE.fullmatch(value)
    if not match or (not partial and (match.group("minor") is None or match.group("patch") is None)):
        raise EcosystemSemanticsError(f"unsupported SemVer: {value!r}")
    core = tuple(int(match.group(name) or 0) for name in ("major", "minor", "patch"))
    prerelease: list[tuple[int, object]] = []
    raw_pre = match.group("pre")
    if raw_pre is not None:
        for identifier in raw_pre.split("."):
            if identifier.isdigit():
                need(not (len(identifier) > 1 and identifier.startswith("0")), "invalid SemVer prerelease")
                prerelease.append((0, int(identifier)))
            else:
                prerelease.append((1, identifier))
    return core, tuple(prerelease) if raw_pre is not None else None


def _semver_compare(left: tuple[tuple[int, int, int], tuple[tuple[int, object], ...] | None],
                    right: tuple[tuple[int, int, int], tuple[tuple[int, object], ...] | None]) -> int:
    if left[0] != right[0]:
        return (left[0] > right[0]) - (left[0] < right[0])
    a, b = left[1], right[1]
    if a is None or b is None:
        return 0 if a is None and b is None else 1 if a is None else -1
    for x, y in zip(a, b):
        if x[0] != y[0]:
            return (x[0] > y[0]) - (x[0] < y[0])
        if x[1] != y[1]:
            return (x[1] > y[1]) - (x[1] < y[1])
    return (len(a) > len(b)) - (len(a) < len(b))


def _parse_events(events: object, parser, comparator) -> tuple[list[tuple[Any, str | None, str | None]], bool]:
    if not isinstance(events, list) or not events:
        return [], True
    intervals: list[tuple[Any, str | None, str | None]] = []
    opened: str | None = None
    previous_end: Any | None = None
    previous_kind: str | None = None
    terminated_unbounded = False
    unsupported = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return [], True
        kind, raw = next(iter(event.items()))
        if not isinstance(raw, str):
            return [], True
        if kind == "introduced" and opened is None:
            try:
                parsed = parser(raw, partial=True)
                if terminated_unbounded:
                    return [], True
                if previous_end is not None:
                    relation = comparator(parsed, previous_end)
                    if relation < 0 or (relation == 0 and previous_kind == "last_affected"):
                        return [], True
            except (EcosystemSemanticsError, ValueError, TypeError):
                return [], True
            opened = raw
        elif kind in ("fixed", "last_affected") and opened is not None:
            try:
                start = parser(opened, partial=True)
                end = parser(raw, partial=True)
                if opened != "0" and comparator(start, end) > 0:
                    return [], True
                intervals.append((start, raw, kind))
                previous_end, previous_kind = end, kind
            except (EcosystemSemanticsError, ValueError, TypeError):
                return [], True
            opened = None
        elif kind == "limit" and opened is not None and raw == "*":
            try:
                intervals.append((parser(opened, partial=True), None, "limit"))
            except (EcosystemSemanticsError, ValueError, TypeError):
                return [], True
            opened = None
            terminated_unbounded = True
        else:
            return [], True
    if opened is not None:
        try:
            intervals.append((parser(opened, partial=True), None, None))
        except (EcosystemSemanticsError, ValueError, TypeError):
            return [], True
    return intervals, unsupported or not intervals


def _matching_affected(advisory: dict[str, Any], ecosystem: str, package: str) -> list[dict[str, Any]]:
    result = []
    affected_rows = advisory.get("affected")
    if not isinstance(affected_rows, list) or any(not isinstance(row, dict) for row in affected_rows):
        raise EcosystemSemanticsError("malformed affected rows")
    for affected in affected_rows:
        item = affected.get("package")
        if isinstance(item, dict) and item.get("ecosystem", "").casefold() == ecosystem.casefold() \
                and item.get("name", "").casefold() == package.casefold():
            result.append(affected)
    return result


def _candidate_status(advisory: dict[str, Any], ecosystem: str, package: str, version: str) -> str:
    """Candidate policy: native parsing, unioned disjoint intervals, fail closed."""
    database_specific = advisory.get("database_specific")
    if (not isinstance(advisory, dict) or advisory.get("withdrawn")
            or not isinstance(database_specific, dict)
            or not database_specific.get("github_reviewed")):
        return UNKNOWN
    try:
        if ecosystem == "PyPI":
            from packaging.version import Version
            parsed = Version(version)
            parser = lambda value, partial=False: Version(value)
            comparator = lambda left, right: (left > right) - (left < right)
        elif ecosystem == "npm":
            parsed = _parse_semver(version)
            parser = _parse_semver
            comparator = _semver_compare
        else:
            return UNKNOWN
    except Exception:
        return UNKNOWN
    try:
        affected_rows = _matching_affected(advisory, ecosystem, package)
    except EcosystemSemanticsError:
        return UNKNOWN
    if not affected_rows:
        return INAPPLICABLE
    unsupported = False
    supported = False
    for affected in affected_rows:
        exact = affected.get("versions", [])
        if not isinstance(exact, list):
            return UNKNOWN
        if isinstance(exact, list) and version in exact:
            return APPLICABLE
        ranges = affected.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            unsupported = True
            continue
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
                unsupported = True
                continue
            intervals, bad = _parse_events(item.get("events"), parser, comparator)
            unsupported = unsupported or bad
            supported = supported or bool(intervals)
            for start, raw_end, end_kind in intervals:
                if ecosystem == "PyPI":
                    from packaging.version import Version
                    end = Version(raw_end) if raw_end is not None else None
                    left = parsed >= start
                    right = True if end is None else parsed <= end if end_kind == "last_affected" else parsed < end
                else:
                    end = _parse_semver(raw_end, partial=True) if raw_end is not None else None
                    left = _semver_compare(parsed, start) >= 0
                    right = True if end is None else _semver_compare(parsed, end) <= 0 if end_kind == "last_affected" else _semver_compare(parsed, end) < 0
                if left and right:
                    return APPLICABLE
    if unsupported or not supported:
        return UNKNOWN
    return INAPPLICABLE


def _range_strings(events: object) -> tuple[list[str], bool]:
    intervals, unsupported = _parse_events(events, _parse_semver, _semver_compare)
    ranges = []
    for _start, raw_end, end_kind in intervals:
        # Reconstructing the raw lower bound is done by the oracle helper below;
        # this helper is used only for npm after raw events are normalized.
        del raw_end, end_kind
    if not isinstance(events, list):
        return [], True
    opened: str | None = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            unsupported = True
            continue
        key, value = next(iter(event.items()))
        if key == "introduced" and opened is None and isinstance(value, str):
            opened = value
        elif key in ("fixed", "last_affected") and opened is not None and isinstance(value, str):
            end_operator = "<=" if key == "last_affected" else "<"
            ranges.append(f">={opened} {end_operator}{value}")
            opened = None
        elif key == "limit" and opened is not None and value == "*":
            ranges.append(f">={opened}")
            opened = None
        else:
            unsupported = True
    if opened is not None:
        ranges.append(f">={opened}")
    return ranges, unsupported


def _pypi_reference_status(advisory: dict[str, Any], package: str, version: str) -> str:
    SpecifierSet, Version, InvalidVersion = _load_packaging()
    try:
        parsed = Version(version)
    except InvalidVersion:
        return UNKNOWN
    try:
        rows = _matching_affected(advisory, "PyPI", package)
    except EcosystemSemanticsError:
        return UNKNOWN
    if not rows:
        return INAPPLICABLE
    unsupported = False
    supported = False
    for affected in rows:
        exact = affected.get("versions", [])
        if not isinstance(exact, list):
            return UNKNOWN
        if version in exact:
            return APPLICABLE
        ranges = affected.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            unsupported = True
            continue
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
                unsupported = True
                continue
            events = item.get("events")
            if not isinstance(events, list):
                unsupported = True
                continue
            # OSV events describe a union of intervals.  A single SpecifierSet
            # would intersect every lower/upper bound and incorrectly turn
            # disjoint intervals into an empty set.
            intervals, bad = _parse_events(
                events,
                lambda value, partial=False: Version(value),
                lambda left, right: (left > right) - (left < right),
            )
            if bad or not intervals:
                unsupported = True
                continue
            for start, raw_end, end_kind in intervals:
                parts = [f">={start}"]
                if raw_end is not None:
                    try:
                        end = Version(raw_end)
                    except InvalidVersion:
                        unsupported = True
                        continue
                    parts.append(("<=" if end_kind == "last_affected" else "<") + str(end))
                try:
                    spec = SpecifierSet(",".join(parts))
                    supported = True
                    if spec.contains(parsed, prereleases=True):
                        return APPLICABLE
                except (InvalidVersion, ValueError):
                    unsupported = True
    if unsupported or not supported:
        return UNKNOWN
    return INAPPLICABLE


def _npm_reference_matches(version: str, ranges: list[str]) -> bool:
    node_path = _node_path()
    script = """
const semver = require('semver');
let raw=''; process.stdin.on('data', c => raw += c);
process.stdin.on('end', () => {
  const input=JSON.parse(raw);
  process.stdout.write(JSON.stringify(input.ranges.some(r => semver.satisfies(input.version, r, {includePrerelease:true}))));
});
"""
    proc = subprocess.run(
        ["node", "-e", script], input=json.dumps({"version": version, "ranges": ranges}),
        text=True, capture_output=True, env={**os.environ, "NODE_PATH": node_path}, check=False,
    )
    need(proc.returncode == 0 and proc.stdout.strip() in ("true", "false"), "npm reference resolver failed")
    return proc.stdout.strip() == "true"


def _npm_reference_status(advisory: dict[str, Any], package: str, version: str) -> str:
    try:
        _parse_semver(version)
    except EcosystemSemanticsError:
        return UNKNOWN
    try:
        rows = _matching_affected(advisory, "npm", package)
    except EcosystemSemanticsError:
        return UNKNOWN
    if not rows:
        return INAPPLICABLE
    unsupported = False
    supported = False
    for affected in rows:
        exact = affected.get("versions", [])
        if not isinstance(exact, list):
            return UNKNOWN
        if version in exact:
            return APPLICABLE
        ranges = affected.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            unsupported = True
            continue
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
                unsupported = True
                continue
            expressions, bad = _range_strings(item.get("events"))
            unsupported = unsupported or bad
            supported = supported or bool(expressions)
            if expressions and _npm_reference_matches(version, expressions):
                return APPLICABLE
    if unsupported or not supported:
        return UNKNOWN
    return INAPPLICABLE


def _reference_status(advisory: dict[str, Any], ecosystem: str, package: str, version: str) -> str:
    if ecosystem == "PyPI":
        return _pypi_reference_status(advisory, package, version)
    if ecosystem == "npm":
        return _npm_reference_status(advisory, package, version)
    return UNKNOWN


def _action_for(decision: str) -> str:
    return {
        APPLICABLE: BLOCK_OR_UPGRADE,
        INAPPLICABLE: NO_ACTION_FOR_ADVISORY,
        UNKNOWN: ABSTAIN_AND_REQUEST_EVIDENCE,
    }.get(decision, ABSTAIN_AND_REQUEST_EVIDENCE)


def _answer_option(ecosystem: str, package: str, version: str, advisory_id: str, decision: str, token: str) -> dict[str, Any]:
    action = _action_for(decision)
    if decision == APPLICABLE:
        text = (f"For {ecosystem}:{package}@{version}, advisory {advisory_id} matches a published affected interval. "
                "Block or upgrade this dependency for this advisory, while keeping the claim limited to version applicability and not exploitability.")
    elif decision == INAPPLICABLE:
        text = (f"For {ecosystem}:{package}@{version}, advisory {advisory_id} matches no published affected interval. "
                "Take no action for this advisory alone, while checking other advisories and application-specific evidence.")
    else:
        text = (f"For {ecosystem}:{package}@{version}, the published evidence cannot be resolved safely for advisory {advisory_id}. "
                "Abstain and request a supported range or exact-version source before recommending a security action.")
    return {
        "answer_token": token,
        "claim": {"decision": decision, "action": action, "scope": "version_applicability_only", "text": text},
    }


def _select_structured_claim_action(options: list[dict[str, Any]], candidate_decision: str,
                                    candidate_action: str) -> dict[str, Any]:
    """Select a structured claim/action; display text is not parsed here."""
    matches = [option for option in options
               if option.get("claim", {}).get("decision") == candidate_decision
               and option.get("claim", {}).get("action") == candidate_action]
    need(len(matches) == 1, "answer options do not contain exactly one candidate claim/action")
    return matches[0]


def _structured_claim_action_correct(claim: dict[str, Any], reference_decision: str,
                                     reference_action: str) -> bool:
    return claim.get("decision") == reference_decision and claim.get("action") == reference_action


def _snapshot_paths(root: Path, kind: str, key: str) -> tuple[Path, Path]:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", key)
    data = root / SNAPSHOT_ROOT / kind / f"{safe}.json"
    return data, data.with_name(data.stem + ".meta.json")


def _write_snapshot(root: Path, kind: str, key: str, raw: bytes, source_url: str, canonical_id: str | None = None) -> dict[str, Any]:
    data_path, meta_path = _snapshot_paths(root, kind, key)
    need(not data_path.exists() and not meta_path.exists(), f"snapshot already exists: {data_path}")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(raw)
    meta = {
        "schema_version": 1, "kind": kind, "source_url": source_url,
        "sha256": hashlib.sha256(raw).hexdigest(), "byte_size": len(raw),
        "captured_utc": datetime.now(timezone.utc).isoformat(),
    }
    if canonical_id is not None:
        meta["canonical_id"] = canonical_id
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return meta


def _read_snapshot(root: Path, kind: str, key: str, expected: dict[str, Any]) -> bytes:
    data_path, meta_path = _snapshot_paths(root, kind, key)
    try:
        raw = data_path.read_bytes()
        meta = strict_json(meta_path.read_bytes())
    except OSError as exc:
        raise EcosystemSemanticsError(f"missing immutable {kind} snapshot: {key}") from exc
    need(isinstance(meta, dict), f"invalid {kind} snapshot metadata: {key}")
    need(meta.get("source_url") == expected.get("source_url"), f"snapshot URL mismatch: {key}")
    need(meta.get("sha256") == expected.get("sha256") and hashlib.sha256(raw).hexdigest() == meta.get("sha256"),
         f"snapshot hash mismatch: {key}")
    need(meta.get("byte_size") == len(raw), f"snapshot size mismatch: {key}")
    return raw


def _available_versions(ecosystem: str, metadata: dict[str, Any]) -> set[str]:
    field = "releases" if ecosystem == "PyPI" else "versions"
    values = metadata.get(field)
    need(isinstance(values, dict), f"registry metadata missing {field}")
    return {str(version) for version in values}


def _build_protocol(root: Path = ROOT) -> dict[str, Any]:
    _load_packaging()
    _node_path()
    registry_rows: dict[str, dict[str, Any]] = {}
    advisory_rows: dict[str, dict[str, Any]] = {}
    for identifier, row in RECORDS.items():
        advisory_url = _source_url(identifier)
        advisory_raw = _fetch(advisory_url)
        advisory = strict_json(advisory_raw)
        need(isinstance(advisory, dict) and advisory.get("id") == identifier, f"advisory identity mismatch: {identifier}")
        advisory_meta = _write_snapshot(root, "advisories", identifier, advisory_raw, advisory_url, identifier)
        advisory_rows[identifier] = {"id": identifier, "source_url": advisory_url, "sha256": advisory_meta["sha256"],
                                     "snapshot": str(_snapshot_paths(root, "advisories", identifier)[0].relative_to(root)).replace("\\", "/")}
        registry_raw = _fetch(row["registry_url"])
        registry = strict_json(registry_raw)
        need(isinstance(registry, dict), f"registry metadata malformed: {row['package']}")
        registry_meta = _write_snapshot(root, "registry", f"{row['ecosystem']}-{row['package']}", registry_raw, row["registry_url"])
        registry_key = f"{row['ecosystem']}-{row['package']}"
        registry_rows[registry_key] = {"ecosystem": row["ecosystem"], "package": row["package"],
                                       "source_url": row["registry_url"], "sha256": registry_meta["sha256"],
                                       "snapshot": str(_snapshot_paths(root, "registry", registry_key)[0].relative_to(root)).replace("\\", "/")}
    raw_cases = []
    for identifier, version in SEED_CASES:
        record = RECORDS[identifier]
        registry_key = f"{record['ecosystem']}-{record['package']}"
        registry_raw = _read_snapshot(root, "registry", registry_key, registry_rows[registry_key])
        metadata = strict_json(registry_raw)
        need(isinstance(metadata, dict) and version in _available_versions(record["ecosystem"], metadata),
             f"seed version is not present in snapshot: {record['package']}@{version}")
        advisory = strict_json(_read_snapshot(root, "advisories", identifier, advisory_rows[identifier]))
        label = _reference_status(advisory, record["ecosystem"], record["package"], version)
        need(label in (APPLICABLE, INAPPLICABLE, UNKNOWN), "reference resolver produced invalid label")
        raw_cases.append({"advisory_id": identifier, "ecosystem": record["ecosystem"], "package": record["package"],
                          "version": version, "reference_label": label})
    rng = random.Random(LAYOUT_SEED)
    rng.shuffle(raw_cases)
    cases = []
    for index, raw in enumerate(raw_cases):
        tokens = list(TOKEN_NAMES)
        rng.shuffle(tokens)
        options = [_answer_option(raw["ecosystem"], raw["package"], raw["version"], raw["advisory_id"], decision, token)
                   for decision, token in zip((APPLICABLE, INAPPLICABLE, UNKNOWN), tokens)]
        rng.shuffle(options)
        case_id = hashlib.sha256(f"{raw['advisory_id']}|{raw['ecosystem']}|{raw['package']}|{raw['version']}".encode()).hexdigest()[:16]
        cases.append({"case_id": case_id, "case_index": index, "advisory_id": raw["advisory_id"],
                      "target": {"ecosystem": raw["ecosystem"], "package": raw["package"], "version": raw["version"]},
                      "options": options, "reference": {"label": raw["reference_label"],
                      "expected_action": _action_for(raw["reference_label"]),
                      "label_source": advisory_rows[raw["advisory_id"]]["snapshot"]}})
    need(Counter(case["reference"]["label"] for case in cases) == Counter({APPLICABLE: 7, INAPPLICABLE: 7}),
         "semantic roster is not balanced")
    return {"schema_version": 1, "status": FROZEN_STATUS, "frozen_date_utc": datetime.now(timezone.utc).date().isoformat(),
            "intent": "SECURITY_REVIEW_GENERAL", "family": "SECURITY_REVIEW",
            "dataset": {"additional_cases": 12, "regression_cases": 2,
                        "candidate_semantics": "PEP 440 Version comparison and strict SemVer interval comparison with prereleases",
                        "reference_resolvers": {"PyPI": "packaging==26.4 SpecifierSet", "npm": "semver@7.8.6 satisfies(includePrerelease=true)"},
                        "registry_snapshot_policy": "Every claimed version is checked against a committed raw registry response and SHA-256 metadata; audit performs no live registry read."},
            "selection": {"seed_case_roster_frozen_before_labels": True, "layout_seed": LAYOUT_SEED,
                          "token_assignment_is_label_blind": True},
            "advisories": advisory_rows, "registries": registry_rows, "cases": cases,
            "contract": {"disjoint_intervals": True, "unsupported_ranges_abstain": True,
                         "answer_selection": "Select the unique option whose claim decision/action matches the candidate output; reference labels are used only after selection for scoring.",
                         "no_human_gold_claim": True}}


def _load_protocol(root: Path = ROOT) -> dict[str, Any]:
    protocol = strict_json((root / PROTOCOL).read_bytes())
    need(isinstance(protocol, dict) and protocol.get("schema_version") == 1 and protocol.get("status") == FROZEN_STATUS,
         "invalid Phase5BO protocol")
    cases = protocol.get("cases")
    need(isinstance(cases, list) and len(cases) == len(SEED_CASES), "Phase5BO case roster changed")
    return protocol


def _load_evidence(root: Path, protocol: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    advisories: dict[str, dict[str, Any]] = {}
    registries: dict[str, dict[str, Any]] = {}
    for identifier, meta in protocol["advisories"].items():
        raw = _read_snapshot(root, "advisories", identifier, meta)
        doc = strict_json(raw)
        need(isinstance(doc, dict) and doc.get("id") == identifier, f"advisory snapshot identity changed: {identifier}")
        advisories[identifier] = doc
    for key, meta in protocol["registries"].items():
        raw = _read_snapshot(root, "registry", key, meta)
        doc = strict_json(raw)
        need(isinstance(doc, dict), f"registry snapshot malformed: {key}")
        registries[key] = doc
    for case in protocol["cases"]:
        key = f"{case['target']['ecosystem']}-{case['target']['package']}"
        need(case["target"]["version"] in _available_versions(case["target"]["ecosystem"], registries[key]),
             f"claimed version missing from immutable snapshot: {case['target']}")
    return advisories, registries


def audit(root: Path = ROOT) -> dict[str, Any]:
    _load_packaging()
    _node_path()
    protocol = _load_protocol(root)
    advisories, registries = _load_evidence(root, protocol)
    candidate_rows = []
    for frozen in protocol["cases"]:
        target = frozen["target"]
        advisory = advisories[frozen["advisory_id"]]
        candidate = _candidate_status(advisory, target["ecosystem"], target["package"], target["version"])
        reference = _reference_status(advisory, target["ecosystem"], target["package"], target["version"])
        need(reference == frozen["reference"]["label"], f"reference label changed: {frozen['case_id']}")
        candidate_action = _action_for(candidate)
        selected = _select_structured_claim_action(frozen["options"], candidate, candidate_action)
        claim = selected["claim"]
        claim_correct = _structured_claim_action_correct(
            claim, reference, frozen["reference"]["expected_action"])
        candidate_rows.append({"case_id": frozen["case_id"], "case_index": frozen["case_index"], "target": target,
                               "reference_label": reference, "candidate_decision": candidate,
                               "candidate_action": candidate_action,
                               "candidate_correct": candidate == reference, "selected_answer_token": selected["answer_token"],
                               "selected_claim": claim, "structured_claim_action_correct": claim_correct})
    candidate_correct = sum(row["candidate_correct"] for row in candidate_rows)
    reference_correct = len(candidate_rows)
    structured_correct = sum(row["structured_claim_action_correct"] for row in candidate_rows)
    option_texts = [option["claim"]["text"] for case in protocol["cases"] for option in case["options"]]
    need(len(set(option_texts)) == len(option_texts), "competing claim text is duplicated")
    need(all(option["claim"]["action"] in {BLOCK_OR_UPGRADE, NO_ACTION_FOR_ADVISORY, ABSTAIN_AND_REQUEST_EVIDENCE}
             for case in protocol["cases"] for option in case["options"]), "invalid answer action")
    return {"schema_version": 1, "status": STATUS, "protocol": str(PROTOCOL).replace("\\", "/"),
            "offline_snapshot_only": True, "registry_snapshot_verification": {"verified": True, "live_registry_reads": 0,
            "registry_snapshots": len(protocol["registries"]), "claimed_versions_verified": len(candidate_rows)},
            "cases": candidate_rows,
            "policies": {"improved_candidate": {"correct": candidate_correct, "incorrect": len(candidate_rows) - candidate_correct, "denominator": len(candidate_rows)},
                         "frozen_external_reference": {"correct": reference_correct, "incorrect": 0, "denominator": len(candidate_rows)},
                         "structured_claim_action_selection": {"correct": structured_correct, "incorrect": len(candidate_rows) - structured_correct, "denominator": len(candidate_rows)}},
            "answer_surface_audit": {"options_per_case": 3, "distinct_claim_texts": len(set(option_texts)),
                                      "reference_label_to_token_mapping_used": False,
                                      "selection_by_candidate_claim_and_action": True,
                                      "selection_contract": "structured_decision_and_action",
                                      "natural_language_answer_evaluation_performed": False,
                                      "natural_language_text_role": "display_only_not_parsed_or_scored"},
            "coverage": {"total_cases": len(candidate_rows), "regression_cases": 2, "additional_unseen_cases": 12,
                         "ecosystems": {"PyPI": sum(row["target"]["ecosystem"] == "PyPI" for row in candidate_rows),
                                        "npm": sum(row["target"]["ecosystem"] == "npm" for row in candidate_rows)},
                         "prerelease_cases": sum("-" in row["target"]["version"] or row["target"]["version"].endswith("pre") or "rc" in row["target"]["version"] for row in candidate_rows)},
            "interpretation": {"all_candidate_cases_resolved": candidate_correct == len(candidate_rows),
                               "structured_claim_actions_resolved": structured_correct == len(candidate_rows),
                               "natural_language_answer_evaluation": {"performed": False, "scored": False,
                                   "reason": "Phase5BO evaluates structured decision/action claims; option prose is display text, not a natural-language model answer."},
                               "independent_human_appsec_gold": False, "external_validation": False,
                               "new_paid_telegraph_execution": False,
                               "summary": "Phase5BO demonstrates ecosystem-native version applicability and offline snapshot reproducibility. It is not human AppSec gold, external adoption, a ranking result or a security clearance."},
            "limits": ["The npm candidate and oracle both implement the SemVer ecosystem contract, so this is a semantic regression and reproducibility result, not an independent human adjudication.",
                       "Registry snapshots prove the captured package-version existence at capture time; they do not prove current registry freshness."]}


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = _build_protocol() if args.freeze else audit()
        _write_once(args.out, payload)
        print(json.dumps({"status": payload["status"], "cases": len(payload.get("cases", [])),
                          "candidate_correct": payload.get("policies", {}).get("improved_candidate", {}).get("correct"),
                          "structured_claim_actions_correct": payload.get("policies", {}).get("structured_claim_action_selection", {}).get("correct"),
                          "offline_snapshot_only": payload.get("offline_snapshot_only")}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(1, "PHASE5BO ECOSYSTEM SEMANTICS FAILED CLOSED: " + str(exc)[:500] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
