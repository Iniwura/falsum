"""Compare FALSUM's pinned ResQ result with the real cargo-audit tool."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import tomllib

from .phase5aj_cross_app_evidence import git_blob
from .phase5bu_resq_solana_lockfile import (
    _fetch_app_source, _load_protocol as _load_phase5bu_protocol,
    _source_spec, audit as phase5bu_audit,
)
from .phase5m_real_source_sensitive_model import ROOT

PROTOCOL_BLOB = "324210d4504c16adb51d3b8fa7b1e9dc09249a23"
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "INSUFFICIENT_EVIDENCE"


class CargoAuditBaselineError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise CargoAuditBaselineError(message)


def _load_protocol(root: Path = ROOT) -> dict:
    raw = (root / "data/phase5bx-cargo-audit-resq-baseline-protocol.json").read_bytes()
    _require(git_blob(raw) == PROTOCOL_BLOB, "Phase5BX frozen protocol changed")
    protocol = json.loads(raw.decode("utf-8", "strict"))
    _require(protocol.get("status") == "PHASE5BX_RESQ_CARGO_AUDIT_BASELINE_FROZEN",
             "unexpected Phase5BX protocol status")
    _require(protocol.get("frozen_before_baseline_adapter_implementation") is True,
             "baseline protocol was not frozen before adapter implementation")
    _require(protocol.get("candidate_boundary", {}).get(
        "falsum_candidate_was_executed_before_this_baseline_freeze") is True,
        "candidate chronology must remain explicit")
    return protocol


def _git_output(db_dir: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(db_dir), *args], text=True, capture_output=True, check=False
    )
    _require(result.returncode == 0, "RustSec database git command failed: " + result.stderr[-500:])
    return result.stdout.strip()


def _verify_database(db_dir: Path, protocol: dict) -> tuple[str, dict[str, str]]:
    db_dir = db_dir.resolve()
    _require(db_dir.is_dir() and (db_dir / ".git").exists(),
             "cargo-audit database must be a local git checkout")
    expected = protocol["advisory_database"]["commit"]
    actual = _git_output(db_dir, "rev-parse", "HEAD")
    _require(actual == expected, "RustSec advisory database commit differs from frozen protocol")
    blobs = {}
    for advisory in protocol["advisory_database"]["advisories"]:
        actual_blob = _git_output(db_dir, "rev-parse", "HEAD:" + advisory["path"])
        _require(actual_blob == advisory["blob"], "RustSec advisory blob changed: " + advisory["id"])
        blobs[advisory["id"]] = actual_blob
    return actual, blobs


def _cargo_audit_json(raw: str | bytes | dict) -> dict:
    if isinstance(raw, dict):
        data = raw
    else:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "strict")
        try:
            data = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise CargoAuditBaselineError("cargo-audit did not emit valid JSON") from exc
    _require(isinstance(data, dict), "cargo-audit JSON root must be an object")
    database = data.get("database")
    lockfile = data.get("lockfile")
    vulnerabilities = data.get("vulnerabilities")
    _require(isinstance(database, dict), "cargo-audit database metadata is missing")
    _require(isinstance(lockfile, dict), "cargo-audit lockfile metadata is missing")
    _require(isinstance(vulnerabilities, dict), "cargo-audit vulnerability object is missing")
    _require(isinstance(database.get("advisory-count"), int), "cargo-audit advisory count is missing")
    _require(isinstance(lockfile.get("dependency-count"), int)
             and lockfile["dependency-count"] > 0, "cargo-audit dependency count is missing")
    rows, count, found = (
        vulnerabilities.get("list"), vulnerabilities.get("count"), vulnerabilities.get("found")
    )
    _require(isinstance(rows, list), "cargo-audit vulnerability list is missing")
    _require(isinstance(count, int) and count == len(rows),
             "cargo-audit vulnerability count does not match its list")
    _require(isinstance(found, bool) and found == bool(rows),
             "cargo-audit found flag does not match its list")
    for index, row in enumerate(rows):
        _require(isinstance(row, dict), f"cargo-audit finding {index} is not an object")
        advisory, package = row.get("advisory"), row.get("package")
        _require(isinstance(advisory, dict) and isinstance(advisory.get("id"), str),
                 f"cargo-audit finding {index} has no advisory identity")
        _require(isinstance(package, dict) and isinstance(package.get("name"), str)
                 and isinstance(package.get("version"), str),
                 f"cargo-audit finding {index} has no package identity")
    return data


def evaluate(protocol, phase5bu_report, cargo_audit_data, *, cargo_audit_exit_code,
             cargo_audit_version, database_commit, database_blobs):
    """Compare the frozen package/advisory pairs without relabeling the reference."""
    _require(cargo_audit_exit_code in (0, 1), "cargo-audit exit code is not a valid audit result")
    expected = protocol["selection"]["case_roster"]
    _require(len(expected) == protocol["selection"]["sample_size"],
             "frozen sample size differs from case roster")
    _require(cargo_audit_version == protocol["baseline"]["version"],
             "cargo-audit version differs from frozen protocol")
    _require(database_commit == protocol["advisory_database"]["commit"],
             "RustSec database commit differs from frozen protocol")
    for advisory in protocol["advisory_database"]["advisories"]:
        _require(database_blobs.get(advisory["id"]) == advisory["blob"],
                 "verified RustSec blob map differs from frozen protocol")

    _require(phase5bu_report.get("status") == "PHASE5BU_RESQ_SOLANA_LOCKFILE_COMPATIBILITY",
             "Phase5BU candidate report is missing or has the wrong status")
    app, frozen_app = phase5bu_report.get("application", {}), protocol["application"]
    for key in ("repository", "commit", "lockfile_git_blob", "package", "resolved_version"):
        _require(app.get(key) == frozen_app[key],
                 "Phase5BU report is not for the frozen ResQ lockfile: " + key)
    phase_rows = phase5bu_report.get("rows")
    _require(isinstance(phase_rows, list), "Phase5BU candidate rows are missing")
    phase_by_id = {row.get("case_id"): row for row in phase_rows if isinstance(row, dict)}
    _require(len(phase_by_id) == len(phase_rows), "Phase5BU case IDs are duplicated")
    _require(set(phase_by_id) == {case["id"] for case in expected},
             "Phase5BU case roster differs from frozen protocol")

    data = _cargo_audit_json(cargo_audit_data)
    selected_ids = {case["advisory"] for case in expected}
    matched = {advisory_id: [] for advisory_id in selected_ids}
    all_findings, anchor_findings = [], []
    for finding in data["vulnerabilities"]["list"]:
        advisory_id = finding["advisory"]["id"]
        package = finding["package"]
        item = {"advisory_id": advisory_id, "package": package["name"],
                "version": package["version"]}
        all_findings.append(item)
        if package["name"] == frozen_app["package"]:
            anchor_findings.append(item)
        if advisory_id in selected_ids:
            _require(package["name"] == frozen_app["package"],
                     "selected RustSec advisory appeared for a different package")
            _require(package["version"] == frozen_app["resolved_version"],
                     "selected advisory appeared for a different locked version")
            matched[advisory_id].append(finding)

    rows = []
    for case in expected:
        candidate_row = phase_by_id[case["id"]]
        candidate = candidate_row.get("falsum_candidate")
        reference = candidate_row.get("semver_7_8_6_reference")
        citation_only = candidate_row.get("citation_only_baseline")
        _require(candidate == case["falsum_candidate_status"],
                 "FALSUM candidate differs from frozen Phase5BX record")
        _require(reference == case["semver_reference_status"],
                 "SemVer reference differs from frozen Phase5BX record")
        _require(candidate in (APPLICABLE, INAPPLICABLE, UNKNOWN),
                 "FALSUM candidate status is invalid")
        _require(reference in (APPLICABLE, INAPPLICABLE), "SemVer reference status is invalid")
        _require(citation_only == APPLICABLE, "citation-only control changed unexpectedly")
        occurrences = matched[case["advisory"]]
        _require(len(occurrences) <= 1,
                 "cargo-audit emitted duplicate findings for a frozen package/advisory pair")
        cargo_status = APPLICABLE if occurrences else INAPPLICABLE
        rows.append({
            "case_id": case["id"], "package": case["package"], "version": case["version"],
            "advisory": case["advisory"], "falsum_candidate": candidate,
            "semver_7_8_6_reference": reference, "cargo_audit_0_22_2": cargo_status,
            "citation_only_baseline": citation_only,
        })

    false_accept = sum(r["falsum_candidate"] == APPLICABLE and r["cargo_audit_0_22_2"] == INAPPLICABLE for r in rows)
    false_reject = sum(r["falsum_candidate"] == INAPPLICABLE and r["cargo_audit_0_22_2"] == APPLICABLE for r in rows)
    return {
        "status": "PHASE5BX_RESQ_CARGO_AUDIT_BASELINE",
        "application": {key: frozen_app[key] for key in
                       ("repository", "commit", "lockfile_path", "lockfile_git_blob", "package", "resolved_version")},
        "advisory_database": {
            "repository": protocol["advisory_database"]["repository"], "commit": database_commit,
            "verified_advisory_blobs": database_blobs,
            "cargo_audit_reported_advisory_count": data["database"]["advisory-count"],
            "cargo_audit_reported_last_commit": data["database"].get("last-commit"),
        },
        "baseline": {
            "tool": "cargo-audit", "version": cargo_audit_version, "exit_code": cargo_audit_exit_code,
            "lockfile_dependency_count": data["lockfile"]["dependency-count"],
            "full_lockfile_vulnerability_count": data["vulnerabilities"]["count"],
            "full_lockfile_findings": all_findings, "anchor_lang_findings": anchor_findings,
            "flags": protocol["baseline"]["flags"],
            "runs_outside_application_repository": True, "project_code_executed": False,
        },
        "sample_sizes": {
            "applications": 1, "locked_package_versions": 1, "package_advisory_pairs": len(rows),
            "cargo_audit_full_lockfile_dependencies": data["lockfile"]["dependency-count"],
            "cargo_audit_full_lockfile_findings": data["vulnerabilities"]["count"],
        },
        "aggregate": {
            "falsum_coverage": sum(r["falsum_candidate"] != UNKNOWN for r in rows),
            "falsum_abstentions": sum(r["falsum_candidate"] == UNKNOWN for r in rows),
            "cargo_audit_pair_coverage": len(rows),
            "falsum_cargo_audit_agreement": sum(r["falsum_candidate"] == r["cargo_audit_0_22_2"] for r in rows),
            "falsum_false_acceptances_vs_cargo_audit": false_accept,
            "falsum_false_rejections_vs_cargo_audit": false_reject,
            "semver_cargo_audit_agreement": sum(r["semver_7_8_6_reference"] == r["cargo_audit_0_22_2"] for r in rows),
            "citation_only_false_applicables_vs_cargo_audit": sum(
                r["citation_only_baseline"] == APPLICABLE and r["cargo_audit_0_22_2"] == INAPPLICABLE for r in rows
            ),
        },
        "rows": rows,
        "interpretation": {
            "cargo_audit_is_human_appsec_gold": False,
            "falsum_false_acceptance_and_rejection_are_human_gold_rates": False,
            "full_lockfile_scan_is_falsum": False, "full_dependency_security_clearance": False,
            "program_source_analysis": False, "independent_application_adoption": False,
            "telegraph_network_improvement": False,
            "candidate_previously_executed_before_baseline_freeze": True,
            "post_hoc_independent_tool_corroboration_not_blind_holdout": True,
        },
    }


def run(db_dir: Path, root: Path = ROOT) -> dict:
    protocol = _load_protocol(root)
    db_commit, db_blobs = _verify_database(db_dir, protocol)
    phase5bu_protocol = _load_phase5bu_protocol(root)
    cache = {}

    def fetch(spec):
        key = (spec["repo"], spec["commit"], spec["path"], spec["blob"])
        if key not in cache:
            cache[key] = _fetch_app_source(spec)
        return cache[key]

    phase5bu_report = phase5bu_audit(root, fetcher=fetch)
    app = phase5bu_protocol["application"]
    lock_source = next(row for row in app["sources"] if row["key"] == "resolved_lockfile")
    lock_spec = _source_spec(app["repository"], app["commit"], lock_source)
    lock_bytes = fetch(lock_spec)
    _require(git_blob(lock_bytes) == protocol["application"]["lockfile_git_blob"],
             "downloaded ResQ Cargo.lock differs from frozen Git blob")
    parsed = tomllib.loads(lock_bytes.decode("utf-8", "strict"))
    packages = [row for row in parsed.get("package", [])
                if isinstance(row, dict) and row.get("name") == protocol["application"]["package"]]
    _require(len(packages) == 1 and packages[0].get("version") == protocol["application"]["resolved_version"],
             "ResQ lockfile package/version differs from frozen pair roster")

    version_result = subprocess.run(["cargo", "audit", "--version"], text=True,
                                     capture_output=True, check=False)
    version_text = (version_result.stdout + "\n" + version_result.stderr).strip()
    match = re.search(r"\b(\d+\.\d+\.\d+)\b", version_text)
    _require(version_result.returncode == 0 and match is not None, "could not read cargo-audit version")
    tool_version = match.group(1)
    _require(tool_version == protocol["baseline"]["version"],
             "installed cargo-audit version differs from frozen protocol")
    rust_result = subprocess.run(["rustc", "--version"], text=True,
                                  capture_output=True, check=False)
    rust_match = re.search(r"\b(\d+\.\d+\.\d+)\b", rust_result.stdout)
    _require(rust_result.returncode == 0 and rust_match is not None
             and rust_match.group(1) == protocol["baseline"]["rust_toolchain"],
             "active rustc version differs from frozen cargo-audit toolchain")

    with tempfile.TemporaryDirectory(prefix="falsum-phase5bx-") as temp:
        temp_dir = Path(temp)
        lock_path = temp_dir / "Cargo.lock"
        lock_path.write_bytes(lock_bytes)
        command = ["cargo", "audit", "--no-fetch", "--stale", "--no-yanked",
                   "--db", str(db_dir.resolve()), "--file", str(lock_path), "--json"]
        env = {**os.environ, "CARGO_TERM_COLOR": "never", "NO_COLOR": "1"}
        result = subprocess.run(command, cwd=temp_dir, env=env, text=True,
                                capture_output=True, check=False)
        _require(result.returncode in (0, 1), "cargo-audit execution failed: " + result.stderr[-1200:])
        output = result.stdout.strip() or result.stderr.strip()
        report = evaluate(
            protocol, phase5bu_report, _cargo_audit_json(output),
            cargo_audit_exit_code=result.returncode, cargo_audit_version=tool_version,
            database_commit=db_commit, database_blobs=db_blobs,
        )
        report["execution"] = {
            "command": command,
            "working_directory": "temporary directory outside the pinned application repository",
            "stderr_tail": result.stderr[-1000:] if result.stderr else "",
        }
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.db_dir)
        with args.out.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
        print(json.dumps({
            "status": report["status"], "sample_sizes": report["sample_sizes"],
            "aggregate": report["aggregate"],
            "full_lockfile_findings": report["baseline"]["full_lockfile_vulnerability_count"],
        }, sort_keys=True))
        return 0
    except (CargoAuditBaselineError, OSError, ValueError, KeyError, TypeError) as exc:
        print("Phase5BX error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
