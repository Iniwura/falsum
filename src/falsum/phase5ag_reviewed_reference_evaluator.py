"""Phase 5AG: bounded, source-authenticated per-reference advisory evaluation.

Separate from the frozen Phase 5Y/5Z/5AA lodash historical gates. This engine
does not infer source authenticity from user inputs and never grants a security
clearance. It uses three Git-reviewed source blobs frozen in a prior commit.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import re

from .phase4l_external_receipt_evidence import git_blob_sha
from .phase5m_real_source_sensitive_model import ROOT

PREREG = "data/phase5ag-multiecosystem-reviewed-source-preregistration.json"
PREREG_BLOB = "c396cede959429ff32eff499156961e17546b3e3"
UPSTREAM = "github/advisory-database"
UPSTREAM_COMMIT = "76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
EXPECTED_IDS = (
    "GHSA-wf5p-g6vw-rhxx",
    "GHSA-xj5v-6v4g-jfw6",
    "GHSA-7mqq-6cf9-v2qp",
)
APPLICABLE = "VERIFIED_APPLICABLE"
INAPPLICABLE = "VERIFIED_INAPPLICABLE"
UNKNOWN = "UNKNOWN_SOURCE"
INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
STATUSES = frozenset((APPLICABLE, INAPPLICABLE, UNKNOWN, INSUFFICIENT))
NUMERIC = re.compile(r"^(?:0|[0-9]+(?:\.[0-9]+){2,3})$")
ID = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")


class SourceEvidenceError(ValueError):
    """A trusted source is absent, tampered with, ambiguous, or malformed."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise SourceEvidenceError(message)


def unique_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        ensure(key not in result, "duplicate JSON object key in original Git evidence")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SourceEvidenceError("malformed source JSON") from error


def frozen_protocol(root: Path = ROOT) -> dict:
    raw = (root / PREREG).read_bytes()
    ensure(git_blob_sha(raw) == PREREG_BLOB,
           "Phase 5AG preregistration has changed since it was frozen")
    p = strict_json(raw)
    ensure(isinstance(p, dict)
           and p.get("schema_version") == 1
           and p.get("status") ==
           "PHASE5AG_REVIEWED_GHSA_MULTI_ECOSYSTEM_PROTOCOL_PREREGISTERED_BEFORE_EVALUATOR_IMPLEMENTATION"
           and p.get("source_repository") == UPSTREAM
           and p.get("source_commit") == UPSTREAM_COMMIT
           and p.get("source_count") == 3,
           "invalid upstream source preregistration")
    rows = p.get("source_records")
    ensure(isinstance(rows, list)
           and [x.get("id") for x in rows if isinstance(x, dict)] == list(EXPECTED_IDS)
           and len(rows) == 3, "missing or reordered original advisory sources")
    limits = p.get("explicit_limits")
    ensure(isinstance(limits, dict) and len(limits) >= 6
           and all(v is True for v in limits.values()),
           "historical and evaluation scope limits were relaxed")
    return p


def checked_file(root: Path, relative: str, max_bytes: int = 100_000) -> bytes:
    ensure(isinstance(relative, str) and not relative.startswith("/")
           and ".." not in Path(relative).parts
           and "\\" not in relative,
           "invalid evidence path")
    path = root / relative
    ensure(path.is_file() and not path.is_symlink()
           and 0 < path.stat().st_size <= max_bytes,
           "original reviewed evidence must be a bounded regular file")
    return path.read_bytes()


def reviewed_sources(root: Path = ROOT) -> tuple[dict, dict]:
    """Return (identifier index, verified sources); fail closed on any tampering."""
    manifest = frozen_protocol(root)
    sources: dict[str, dict] = {}
    by_identifier: dict[str, dict] = {}
    for spec in manifest["source_records"]:
        ensure(type(spec) is dict and
               set(("id", "ecosystem", "package",
                    "upstream_source_path", "original_upstream_git_blob_sha1",
                    "local_file", "upstream_reviewed_at", "original_modified_at"))
               <= set(spec), "incomplete source identity")
        identifier = spec["id"]
        ensure(type(identifier) is str and ID.fullmatch(identifier) is not None,
               "invalid pinned GHSA ID")
        ensure(type(spec["original_upstream_git_blob_sha1"]) is str and
               re.fullmatch(r"[0-9a-f]{40}", spec["original_upstream_git_blob_sha1"])
               is not None, "invalid pinned source hash")
        ensure(type(spec["upstream_source_path"]) is str and
               spec["upstream_source_path"].startswith("advisories/github-reviewed/")
               and spec["upstream_source_path"].endswith("/" + identifier + ".json"),
               "untrusted upstream source path")
        expected_local = "evidence/phase5ag-reviewed-advisories/" + identifier + ".json"
        ensure(spec["local_file"] == expected_local, "untrusted local source path")
        raw = checked_file(root, expected_local)
        ensure(git_blob_sha(raw) == spec["original_upstream_git_blob_sha1"],
               "original reviewed Git advisory byte identity changed")
        advisory = strict_json(raw)
        ensure(isinstance(advisory, dict)
               and advisory.get("id") == identifier
               and advisory.get("modified") == spec["original_modified_at"]
               and isinstance(advisory.get("published"), str)
               and isinstance(advisory.get("affected"), list)
               and len(advisory["affected"]) > 0
               and isinstance(advisory.get("aliases"), list),
               "authenticated advisory semantics missing or contradictory")
        review = advisory.get("database_specific")
        ensure(isinstance(review, dict)
               and review.get("github_reviewed") is True
               and review.get("github_reviewed_at") == spec["upstream_reviewed_at"],
               "upstream GitHub-reviewed status not authenticated")
        ensure(any(isinstance(row, dict)
                   and isinstance(row.get("package"), dict)
                   and row["package"].get("ecosystem") == spec["ecosystem"]
                   and row["package"].get("name") == spec["package"]
                   for row in advisory["affected"]),
               "reviewed Git record no longer describes the frozen target package")
        src = {"id": identifier, "spec": spec, "data": advisory}
        sources[identifier] = src
        aliases = [identifier] + advisory["aliases"]
        ensure(all(isinstance(alias, str) and alias for alias in aliases)
               and len(set(aliases)) == len(aliases),
               "invalid original advisory aliases")
        for alias in aliases:
            ensure(alias not in by_identifier,
                   "ambiguous reviewed advisory alias across sources")
            by_identifier[alias] = src
    ensure(set(sources) == set(EXPECTED_IDS),
           "original three-source verified corpus incomplete")
    return by_identifier, sources


def numbers(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or len(value) > 48 or not NUMERIC.fullmatch(value):
        return None
    segments = tuple(int(x) for x in value.split("."))
    if any(n > 999999 for n in segments):
        return None
    return segments


def compare(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    size = max(len(a), len(b))
    aa = a + (0,) * (size - len(a))
    bb = b + (0,) * (size - len(b))
    return (aa > bb) - (aa < bb)


def range_status(events: object, version: tuple[int, ...]) -> str:
    """Support bounded OSV introduced/fixed/last_affected numeric intervals only.

    Unknown event types, complex prerelease ordering and conflicting event
    streams return INSUFFICIENT; they are never inferred as inapplicable.
    """
    if not isinstance(events, list) or not events:
        return INSUFFICIENT
    opened: tuple[int, ...] | None = None
    seen = False
    matched = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return INSUFFICIENT
        key, value = next(iter(event.items()))
        parsed = numbers(value)
        if parsed is None:
            return INSUFFICIENT
        if key == "introduced":
            if opened is not None:
                return INSUFFICIENT
            opened = parsed
            seen = True
        elif key in ("fixed", "last_affected"):
            if opened is None or compare(parsed, opened) < 0:
                return INSUFFICIENT
            left = compare(version, opened) >= 0
            right = compare(version, parsed) < 0 if key == "fixed" else compare(version, parsed) <= 0
            matched = matched or (left and right)
            opened = None
        else:
            return INSUFFICIENT
    if opened is not None and compare(version, opened) >= 0:
        matched = True
    return APPLICABLE if matched else INAPPLICABLE if seen else INSUFFICIENT


def package_status(source: dict, target: Mapping[str, object]) -> tuple[str, str]:
    ecosystem = target.get("ecosystem")
    package = target.get("package")
    version = numbers(target.get("version"))
    if not isinstance(ecosystem, str) or not ecosystem.strip() or not isinstance(package, str) or not package.strip():
        return INSUFFICIENT, "MISSING_PACKAGE_CONTEXT"
    selected = []
    for row in source["data"]["affected"]:
        if not isinstance(row, dict) or not isinstance(row.get("package"), dict):
            return INSUFFICIENT, "MALFORMED_AFFECTED_PACKAGE_RECORD"
        pkg = row["package"]
        if pkg.get("ecosystem") == ecosystem and pkg.get("name") == package:
            selected.append(row)
    if not selected:
        return INAPPLICABLE, "SOURCE_TARGET_PACKAGE_MISMATCH_NOT_SECURITY_CLEARANCE"
    if version is None:
        return INSUFFICIENT, "UNSUPPORTED_OR_MISSING_VERSION"
    if source["data"].get("withdrawn"):
        return INSUFFICIENT, "WITHDRAWN_SOURCE_REQUIRES_NEW_REVIEW"
    uncertain = False
    observed = False
    for row in selected:
        ranges = row.get("ranges")
        if not isinstance(ranges, list) or not ranges:
            uncertain = True
            continue
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
                uncertain = True
                continue
            observed = True
            status = range_status(item.get("events"), version)
            if status == APPLICABLE:
                return APPLICABLE, "IN_PINNED_REVIEWED_AFFECTED_VERSION_INTERVAL"
            if status == INSUFFICIENT:
                uncertain = True
    if uncertain or not observed:
        return INSUFFICIENT, "UNSUPPORTED_OR_CONFLICTING_VERSION_INTERVAL"
    return INAPPLICABLE, "OUTSIDE_PINNED_REVIEWED_AFFECTED_VERSION_INTERVALS"


def evaluate(target: object, references: object, *, root: Path = ROOT) -> dict:
    index, sources = reviewed_sources(root)
    ensure(isinstance(references, list) and len(references) <= 100,
           "references must be a bounded list, not a response-body provenance claim")
    # A missing target is a valid *uncertain* result, never a security approval.
    if not isinstance(target, dict) or set(target) != {"ecosystem", "package", "version"}:
        target = {"ecosystem": None, "package": None, "version": None}
    results = []
    seen: set[str] = set()
    for candidate in references:
        base = {
            "input_reference": candidate if isinstance(candidate, str) and len(candidate) <= 128 else None,
            "canonical_ghsa_id": None,
            "decision": INSUFFICIENT,
            "reason_code": "MALFORMED_REFERENCE",
            "source_url": None,
            "original_git_blob_sha1": None,
            "source_modified_at": None,
            "source_is_current_feed": False,
        }
        if isinstance(candidate, str) and 0 < len(candidate) <= 128:
            source = index.get(candidate)
            if source is None:
                base["decision"] = UNKNOWN
                base["reason_code"] = "IDENTIFIER_NOT_IN_FROZEN_AUTHENTICATED_ROSTER"
            else:
                spec = source["spec"]
                base["canonical_ghsa_id"] = source["id"]
                base["source_url"] = (
                    "https://github.com/" + UPSTREAM + "/blob/" + UPSTREAM_COMMIT +
                    "/" + spec["upstream_source_path"]
                )
                base["original_git_blob_sha1"] = spec["original_upstream_git_blob_sha1"]
                base["source_modified_at"] = spec["original_modified_at"]
                if source["id"] in seen:
                    base["reason_code"] = "DUPLICATE_GHSA_OR_ALIAS_NOT_DOUBLE_COUNTED"
                else:
                    seen.add(source["id"])
                    base["decision"], base["reason_code"] = package_status(source, target)
        results.append(base)
    return {
        "schema_version": 1,
        "status": "PHASE5AG_BOUNDED_AUTHENTICATED_PER_REFERENCE_EVALUATION",
        "source_repository": UPSTREAM,
        "source_commit": UPSTREAM_COMMIT,
        "source_roster_git_blob_sha1": PREREG_BLOB,
        "original_git_reviewed_advisories_verified": len(sources),
        "target": {k: target.get(k) if isinstance(target.get(k), str)
                    and len(target[k]) <= 128 else None
                   for k in ("ecosystem", "package", "version")},
        "reference_decisions": results,
        "decision_counts": {status: sum(r["decision"] == status for r in results)
                            for status in (APPLICABLE, INAPPLICABLE, UNKNOWN, INSUFFICIENT)},
        "coverage_is_complete": False,
        "security_clearance_granted": False,
        "independent_expert_appsec_gold": 0,
        "new_actual_miner_result_evaluated": False,
        "new_independent_developer_adoption_proved": False,
        "registered_telegraph_network_evaluator": False,
        "current_advisory_freshness_verified": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystem", required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--reference", action="append", required=True,
                        help="Repeat for each GHSA ID or CVE alias")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    result = evaluate({"ecosystem": args.ecosystem, "package": args.package,
                       "version": args.version}, args.reference)
    ensure(args.out.parent.is_dir() and not args.out.is_symlink(),
           "output parent directory missing or output is symlink")
    # x mode never overwrites a previous reviewer result.
    with args.out.open("x", encoding="utf-8", newline="\n") as file:
        json.dump(result, file, indent=2, sort_keys=True)
        file.write("\n")
    print(json.dumps({"status": result["status"], "decision_counts": result["decision_counts"],
                      "original_verified_sources": result["original_git_reviewed_advisories_verified"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
