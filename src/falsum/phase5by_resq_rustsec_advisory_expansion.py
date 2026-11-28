"""Source-authenticated RustSec applicability replay on the full ResQ lockfile.

This checks package-version applicability only. It does not inspect program code,
call sites, reachability, runtime behavior, or exploitability.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from .phase5aj_cross_app_evidence import git_blob
from .phase5bu_resq_solana_lockfile import (
    _fetch_app_source,
    _load_protocol as _load_phase5bu_protocol,
    _source_spec,
)
from .phase5bx_cargo_audit_resq_baseline import run as run_phase5bx
from .phase5bo_ecosystem_semantics import EcosystemSemanticsError, _parse_semver, _semver_compare
from .phase5m_real_source_sensitive_model import ROOT

PROTOCOL_BLOB = "88f8150d86bf621a5380a250df46c0b080bde868"
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "INSUFFICIENT_EVIDENCE"
_SIMPLE_CARGO_RANGE = re.compile(
    r"^\s*(>=|>|<=|<|=)\s*(v?\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?)\s*$"
)


class ResQAdvisoryExpansionError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ResQAdvisoryExpansionError(message)


def _load_protocol(root: Path = ROOT) -> dict:
    raw = (root / "data/phase5by-resq-rustsec-advisory-expansion-protocol.json").read_bytes()
    _require(git_blob(raw) == PROTOCOL_BLOB, "Phase5BY frozen protocol changed")
    protocol = json.loads(raw.decode("utf-8", "strict"))
    _require(
        protocol.get("status") == "PHASE5BY_RESQ_RUSTSEC_ADVISORY_EXPANSION_FROZEN",
        "unexpected Phase5BY protocol status",
    )
    _require(protocol.get("frozen_before_candidate_implementation") is True,
             "Phase5BY protocol was not frozen before candidate implementation")
    _require(protocol.get("candidate_boundary", {}).get(
        "candidate_has_not_been_executed_on_new_advisories"
    ) is True, "candidate chronology changed")
    _require(len(protocol["advisory_database"]["new_advisories"]) == 4,
             "Phase5BY new-case roster changed")
    _require(len(protocol["advisory_database"]["calibration_advisories"]) == 2,
             "Phase5BY calibration roster changed")
    return protocol


def _git_output(db_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(db_dir), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    _require(result.returncode == 0,
             "RustSec database git command failed: " + result.stderr[-500:])
    return result.stdout.strip()


def _verify_database(db_dir: Path, protocol: dict) -> dict[str, str]:
    db_dir = db_dir.resolve()
    _require(db_dir.is_dir() and (db_dir / ".git").exists(),
             "RustSec database must be a local git checkout")
    actual = _git_output(db_dir, "rev-parse", "HEAD")
    expected = protocol["advisory_database"]["commit"]
    _require(actual == expected, "RustSec database commit differs from frozen protocol")
    verified = {}
    for case in (
        protocol["advisory_database"]["new_advisories"]
        + protocol["advisory_database"]["calibration_advisories"]
    ):
        blob = _git_output(db_dir, "rev-parse", "HEAD:" + case["path"])
        _require(blob == case["blob"], "RustSec advisory blob changed: " + case["id"])
        verified[case["id"]] = blob
    return verified


def _frontmatter(raw: bytes, expected_id: str, expected_package: str) -> dict:
    text = raw.decode("utf-8", "strict")
    match = re.search(r"(?s)\A\x60{3}toml\s*\n(.*?)\n\x60{3}\s*(?:\n|\Z)", text)
    _require(match is not None, "RustSec advisory TOML frontmatter is missing")
    metadata = tomllib.loads(match.group(1))
    advisory = metadata.get("advisory")
    versions = metadata.get("versions")
    _require(isinstance(advisory, dict), "RustSec advisory identity is missing")
    _require(advisory.get("id") == expected_id, "RustSec advisory ID changed")
    _require(advisory.get("package") == expected_package, "RustSec package identity changed")
    _require(isinstance(versions, dict), "RustSec versions table is missing")
    for field in ("patched", "unaffected"):
        value = versions.get(field, [])
        _require(isinstance(value, list) and all(isinstance(item, str) for item in value),
                 "RustSec versions." + field + " must be a string array")
    return metadata


def _candidate_range_matches(version: str, requirement: str) -> bool | None:
    """Use FALSUM's Python SemVer implementation for the supported Cargo subset."""
    match = _SIMPLE_CARGO_RANGE.fullmatch(requirement)
    if not match:
        return None
    operator, boundary_text = match.groups()
    try:
        value = _parse_semver(version)
        boundary = _parse_semver(boundary_text.lstrip("v"), partial=True)
    except (EcosystemSemanticsError, TypeError, ValueError):
        return None
    comparison = _semver_compare(value, boundary)
    return {
        ">=": comparison >= 0,
        ">": comparison > 0,
        "<=": comparison <= 0,
        "<": comparison < 0,
        "=": comparison == 0,
    }[operator]


def _node_range_matches(version: str, requirement: str) -> bool | None:
    """Independent semver@7.8.6 range reference for the same pinned source."""
    if not _SIMPLE_CARGO_RANGE.fullmatch(requirement):
        return None
    node_path = os.environ.get("FALSUM_PHASE5BO_NODE_PATH")
    if not node_path:
        return None
    script = r"""
const semver = require('semver');
let raw = '';
process.stdin.on('data', chunk => raw += chunk);
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(raw);
    const valid = semver.validRange(input.requirement, {includePrerelease: true});
    if (valid === null) {
      process.stdout.write('UNKNOWN');
      return;
    }
    process.stdout.write(
      semver.satisfies(input.version, valid, {includePrerelease: true})
        ? 'MATCH' : 'NO_MATCH'
    );
  } catch (_) {
    process.stdout.write('UNKNOWN');
  }
});
"""
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps({"version": version, "requirement": requirement}),
        text=True,
        capture_output=True,
        env={**os.environ, "NODE_PATH": node_path},
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    if value == "MATCH":
        return True
    if value == "NO_MATCH":
        return False
    return None


def _candidate_status(version: str, versions: dict) -> str:
    """Mirror RustSec's affected-range complement using FALSUM's own SemVer parser.

    RustSec treats the union of patched and unaffected VersionReq ranges as
    unaffected. With no ranges, all versions are affected. Unsupported syntax
    produces an abstention rather than a guessed result.
    """
    ranges = versions.get("patched", []) + versions.get("unaffected", [])
    if not ranges:
        return APPLICABLE
    unsupported = False
    matched = False
    for requirement in ranges:
        result = _candidate_range_matches(version, requirement)
        if result is None:
            unsupported = True
        elif result:
            matched = True
    if matched:
        return INAPPLICABLE
    if unsupported:
        return UNKNOWN
    return APPLICABLE


def _reference_status(version: str, versions: dict) -> str:
    ranges = versions.get("patched", []) + versions.get("unaffected", [])
    if not ranges:
        return APPLICABLE
    unsupported = False
    matched = False
    for requirement in ranges:
        result = _node_range_matches(version, requirement)
        if result is None:
            unsupported = True
        elif result:
            matched = True
    if matched:
        return INAPPLICABLE
    if unsupported:
        return UNKNOWN
    return APPLICABLE

def _load_lockfile(root: Path, protocol: dict) -> tuple[bytes, dict]:
    app_protocol = _load_phase5bu_protocol(root)
    app = app_protocol["application"]
    source = next(row for row in app["sources"] if row["key"] == "resolved_lockfile")
    spec = _source_spec(app["repository"], app["commit"], source)
    raw = _fetch_app_source(spec)
    _require(git_blob(raw) == protocol["application"]["lockfile_git_blob"],
             "downloaded ResQ Cargo.lock differs from the frozen Git blob")
    parsed = tomllib.loads(raw.decode("utf-8", "strict"))
    packages = {}
    for row in parsed.get("package", []):
        if not isinstance(row, dict):
            continue
        if row.get("source") != "registry+https://github.com/rust-lang/crates.io-index":
            continue
        name, version = row.get("name"), row.get("version")
        if isinstance(name, str) and isinstance(version, str):
            packages.setdefault((name, version), []).append(row)
    return raw, packages


def evaluate(protocol: dict, db_dir: Path, phase5bx_report: dict,
             lock_packages: dict, verified_blobs: dict) -> dict:
    new_rows = []
    for case in protocol["advisory_database"]["new_advisories"]:
        package_key = (case["package"], case["version"])
        _require(len(lock_packages.get(package_key, [])) == 1,
                 "frozen package/version is not unique in ResQ Cargo.lock: " + case["package"])
        raw = (db_dir / case["path"]).read_bytes()
        _require(git_blob(raw) == case["blob"], "advisory bytes differ from frozen blob")
        metadata = _frontmatter(raw, case["id"], case["package"])
        candidate = _candidate_status(case["version"], metadata["versions"])
        reference = _reference_status(case["version"], metadata["versions"])
        findings = [
            item for item in phase5bx_report["baseline"]["full_lockfile_findings"]
            if item["advisory_id"] == case["id"]
            and item["package"] == case["package"]
            and item["version"] == case["version"]
        ]
        baseline = APPLICABLE if findings else INAPPLICABLE
        _require(baseline == case["cargo_audit_status"],
                 "pinned cargo-audit result differs from frozen baseline for " + case["id"])
        new_rows.append({
            "case_id": case["id"],
            "package": case["package"],
            "version": case["version"],
            "advisory": case["id"],
            "advisory_blob": verified_blobs[case["id"]],
            "patched_ranges": metadata["versions"].get("patched", []),
            "unaffected_ranges": metadata["versions"].get("unaffected", []),
            "affected_functions_present": bool(metadata.get("affected", {}).get("functions")),
            "falsum_candidate": candidate,
            "semver_7_8_6_reference": reference,
            "cargo_audit_0_22_2": baseline,
            "citation_only_baseline": APPLICABLE,
        })

    calibration_rows = []
    phase5bx_rows = {row["advisory"]: row for row in phase5bx_report["rows"]}
    for case in protocol["advisory_database"]["calibration_advisories"]:
        raw = (db_dir / case["path"]).read_bytes()
        _require(git_blob(raw) == case["blob"], "calibration advisory bytes changed")
        metadata = _frontmatter(raw, case["id"], case["package"])
        candidate = _candidate_status(case["version"], metadata["versions"])
        reference = _reference_status(case["version"], metadata["versions"])
        baseline_row = phase5bx_rows.get(case["id"])
        _require(baseline_row is not None, "Phase5BX calibration row is missing")
        baseline = baseline_row["cargo_audit_0_22_2"]
        _require(baseline == case["cargo_audit_status"],
                 "Phase5BX calibration status differs from frozen protocol")
        calibration_rows.append({
            "case_id": case["id"],
            "package": case["package"],
            "version": case["version"],
            "advisory": case["id"],
            "advisory_blob": verified_blobs[case["id"]],
            "patched_ranges": metadata["versions"].get("patched", []),
            "unaffected_ranges": metadata["versions"].get("unaffected", []),
            "falsum_candidate": candidate,
            "semver_7_8_6_reference": reference,
            "cargo_audit_0_22_2": baseline,
            "citation_only_baseline": APPLICABLE,
            "is_prior_calibration_only": True,
        })

    all_rows = new_rows + calibration_rows

    def metrics(rows):
        return {
            "sample_size": len(rows),
            "falsum_coverage": sum(row["falsum_candidate"] != UNKNOWN for row in rows),
            "falsum_abstentions": sum(row["falsum_candidate"] == UNKNOWN for row in rows),
            "agreement_with_cargo_audit": sum(
                row["falsum_candidate"] == row["cargo_audit_0_22_2"] for row in rows
            ),
            "agreement_with_semver_7_8_6": sum(
                row["falsum_candidate"] == row["semver_7_8_6_reference"] for row in rows
            ),
            "semver_reference_coverage": sum(
                row["semver_7_8_6_reference"] != UNKNOWN for row in rows
            ),
            "false_acceptances_vs_cargo_audit": sum(
                row["falsum_candidate"] == APPLICABLE
                and row["cargo_audit_0_22_2"] == INAPPLICABLE for row in rows
            ),
            "false_rejections_vs_cargo_audit": sum(
                row["falsum_candidate"] == INAPPLICABLE
                and row["cargo_audit_0_22_2"] == APPLICABLE for row in rows
            ),
            "false_acceptances_vs_semver_7_8_6": sum(
                row["falsum_candidate"] == APPLICABLE
                and row["semver_7_8_6_reference"] == INAPPLICABLE for row in rows
            ),
            "false_rejections_vs_semver_7_8_6": sum(
                row["falsum_candidate"] == INAPPLICABLE
                and row["semver_7_8_6_reference"] == APPLICABLE for row in rows
            ),
            "citation_only_false_applicables_vs_cargo_audit": sum(
                row["citation_only_baseline"] == APPLICABLE
                and row["cargo_audit_0_22_2"] == INAPPLICABLE for row in rows
            ),
        }

    return {
        "status": "PHASE5BY_RESQ_RUSTSEC_ADVISORY_EXPANSION",
        "protocol_blob": PROTOCOL_BLOB,
        "application": protocol["application"],
        "advisory_database": {
            "repository": protocol["advisory_database"]["repository"],
            "commit": protocol["advisory_database"]["commit"],
            "verified_advisory_blobs": verified_blobs,
        },
        "baseline": {
            "tool": "cargo-audit",
            "version": phase5bx_report["baseline"]["version"],
            "lockfile_dependencies": phase5bx_report["baseline"]["lockfile_dependency_count"],
            "full_lockfile_findings": phase5bx_report["baseline"]["full_lockfile_findings"],
            "full_lockfile_finding_count": phase5bx_report["baseline"]["full_lockfile_vulnerability_count"],
        },
        "sample_sizes": {
            "applications": 1,
            "new_package_advisory_pairs": len(new_rows),
            "prior_calibration_pairs": len(calibration_rows),
            "combined_package_advisory_pairs": len(all_rows),
        },
        "new_case_metrics": metrics(new_rows),
        "calibration_metrics": metrics(calibration_rows),
        "combined_metrics": metrics(all_rows),
        "new_cases": new_rows,
        "calibration_controls": calibration_rows,
        "interpretation": {
            "cargo_audit_is_human_appsec_gold": False,
            "falsum_false_acceptance_and_rejection_are_human_gold_rates": False,
            "new_cases_are_blind_holdout": False,
            "new_cases_are_independent_source_family_holdout": False,
            "calibration_controls_are_held_out": False,
            "full_lockfile_scan_is_falsum": False,
            "program_source_analysis": False,
            "function_reachability_analysis": False,
            "exploitability_assessed": False,
            "independent_application_adoption": False,
            "telegraph_network_improvement": False,
            "scope": "FALSUM package-version applicability on four new advisory records, plus two prior calibration controls",
            "new_case_specificity_measured": False,
        },
    }


def run(db_dir: Path, root: Path = ROOT) -> tuple[dict, dict]:
    protocol = _load_protocol(root)
    verified_blobs = _verify_database(db_dir, protocol)
    lock_bytes, lock_packages = _load_lockfile(root, protocol)
    _require(
        git_blob(lock_bytes) == protocol["application"]["lockfile_git_blob"],
        "ResQ lockfile identity changed",
    )
    phase5bx_report = run_phase5bx(db_dir, root)
    report = evaluate(protocol, db_dir, phase5bx_report, lock_packages, verified_blobs)
    report["application"]["locked_dependency_count_from_cargo_audit"] = (
        phase5bx_report["baseline"]["lockfile_dependency_count"]
    )
    return report, phase5bx_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--baseline-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report, baseline = run(args.db_dir)
        for path, payload in ((args.out, report), (args.baseline_out, baseline)):
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, indent=2, sort_keys=True, allow_nan=False)
                stream.write("\n")
        print(json.dumps({
            "status": report["status"],
            "sample_sizes": report["sample_sizes"],
            "new_case_metrics": report["new_case_metrics"],
            "calibration_metrics": report["calibration_metrics"],
            "combined_metrics": report["combined_metrics"],
        }, sort_keys=True))
        return 0
    except (ResQAdvisoryExpansionError, OSError, ValueError, KeyError, TypeError) as exc:
        print("Phase5BY error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
