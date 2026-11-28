"""Reproducible Cargo.lock compatibility check for a pinned Solana application.

This is a narrow dependency/advisory compatibility harness, not a program scanner.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib
from urllib.request import urlopen

from .phase5aj_cross_app_evidence import git_blob, require, source_bytes
from .phase5bo_ecosystem_semantics import (
    EcosystemSemanticsError,
    _node_path,
    _parse_semver,
    _semver_compare,
)
from .phase5m_real_source_sensitive_model import ROOT

PROTOCOL_BLOB = "9f9345411057dba0fc5acc6485a1e877e8646efb"
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "INSUFFICIENT_EVIDENCE"
MAX_LOCK_BYTES = 1_000_000


def _load_protocol(root: Path = ROOT) -> dict:
    raw = (root / "data/phase5bu-resq-solana-lockfile-protocol.json").read_bytes()
    require(git_blob(raw) == PROTOCOL_BLOB, "precommitted ResQ lockfile protocol changed")
    protocol = json.loads(raw.decode("utf-8", "strict"))
    require(protocol.get("status") == "PHASE5BU_RESQ_SOLANA_LOCKFILE_FROZEN",
            "unexpected Phase5BU protocol status")
    require(protocol.get("selection", {}).get("package_and_advisory_roster_frozen_before_candidate_implementation") is True,
            "package/advisory roster was not frozen")
    require(protocol.get("selection", {}).get("resolved_lockfile_version_frozen_before_candidate_implementation") is True,
            "resolved package version was not frozen")
    return protocol


def _source_spec(repo: str, commit: str, source: dict, *, key: str | None = None) -> dict:
    return {
        "key": key or source["key"],
        "repo": repo,
        "commit": commit,
        "path": source["path"],
        "blob": source["blob"],
    }


def _fetch_app_source(spec: dict, fetcher=None) -> bytes:
    if fetcher is not None:
        return fetcher(spec)
    if spec["path"] != "Cargo.lock":
        return source_bytes(spec)
    url = (
        "https://raw.githubusercontent.com/" + spec["repo"] + "/" +
        spec["commit"] + "/" + spec["path"]
    )
    with urlopen(url, timeout=30) as response:
        raw = response.read(MAX_LOCK_BYTES + 1)
    require(len(raw) <= MAX_LOCK_BYTES, "oversized pinned Cargo.lock")
    require(git_blob(raw) == spec["blob"], "Cargo.lock Git byte identity mismatch")
    return raw


def _cargo_lock_package(raw: bytes, package_name: str) -> dict:
    parsed = tomllib.loads(raw.decode("utf-8", "strict"))
    packages = [
        row for row in parsed.get("package", [])
        if isinstance(row, dict) and row.get("name") == package_name
    ]
    require(len(packages) == 1, "expected exactly one locked " + package_name + " package")
    package = packages[0]
    require(isinstance(package.get("version"), str), "locked package version is missing")
    require(
        package.get("source") == "registry+https://github.com/rust-lang/crates.io-index",
        "anchor-lang is not resolved from the pinned crates.io registry",
    )
    require(isinstance(package.get("checksum"), str) and len(package["checksum"]) == 64,
            "locked package checksum is missing or malformed")
    return package


def _rustsec_interval(raw: bytes, expected_id: str, expected_package: str) -> tuple[str, str]:
    text = raw.decode("utf-8", "strict")
    match = re.search(r"(?m)^\x60{3}toml\s*\n(.*?)\n\x60{3}\s*$", text, flags=re.S)
    require(match is not None, "RustSec advisory TOML frontmatter is missing")
    metadata = tomllib.loads(match.group(1))
    advisory = metadata.get("advisory", {})
    versions = metadata.get("versions", {})
    require(advisory.get("id") == expected_id, "RustSec advisory identity changed")
    require(advisory.get("package") == expected_package, "RustSec package identity changed")
    patched = versions.get("patched")
    unaffected = versions.get("unaffected")
    require(isinstance(patched, list) and len(patched) == 1, "unsupported patched-range shape")
    require(isinstance(unaffected, list) and len(unaffected) == 1, "unsupported unaffected-range shape")
    fixed_match = re.fullmatch(r"\s*>=\s*(\S+)\s*", patched[0])
    introduced_match = re.fullmatch(r"\s*<\s*(\S+)\s*", unaffected[0])
    require(fixed_match is not None and introduced_match is not None,
            "RustSec bounds are not a single half-open SemVer interval")
    introduced, fixed = introduced_match.group(1), fixed_match.group(1)
    _parse_semver(introduced)
    _parse_semver(fixed)
    return introduced, fixed


def _candidate_status(version: str, introduced: str, fixed: str) -> str:
    try:
        value = _parse_semver(version)
        lower = _parse_semver(introduced)
        upper = _parse_semver(fixed)
    except (EcosystemSemanticsError, TypeError, ValueError):
        return UNKNOWN
    return APPLICABLE if (
        _semver_compare(value, lower) >= 0 and _semver_compare(value, upper) < 0
    ) else INAPPLICABLE


def _node_reference_status(version: str, introduced: str, fixed: str) -> str:
    env = {**os.environ, "NODE_PATH": _node_path()}
    probe = subprocess.run(
        ["node", "-e", "process.stdout.write(require('semver/package.json').version || '')"],
        text=True, capture_output=True, env=env, check=False,
    )
    require(probe.returncode == 0 and probe.stdout.strip() == "7.8.6",
            "independent reference must be semver@7.8.6")
    script = """
const semver = require('semver');
let raw = '';
process.stdin.on('data', chunk => raw += chunk);
process.stdin.on('end', () => {
  const input = JSON.parse(raw);
  const range = `>=${input.introduced} <${input.fixed}`;
  const affected = semver.satisfies(input.version, range, {includePrerelease: true});
  process.stdout.write(affected ? 'APPLICABLE' : 'INAPPLICABLE');
});
"""
    result = subprocess.run(
        ["node", "-e", script],
        input=json.dumps({"version": version, "introduced": introduced, "fixed": fixed}),
        text=True, capture_output=True, env=env, check=False,
    )
    require(result.returncode == 0 and result.stdout.strip() in (APPLICABLE, INAPPLICABLE),
            "semver@7.8.6 reference resolver failed: " + result.stderr[-500:])
    return result.stdout.strip()


def audit(root: Path = ROOT, fetcher=None) -> dict:
    protocol = _load_protocol(root)
    app = protocol["application"]
    app_sources = {}
    for source in app["sources"]:
        spec = _source_spec(app["repository"], app["commit"], source)
        app_sources[source["key"]] = _fetch_app_source(spec, fetcher)

    readme = app_sources["readme"].decode("utf-8", "strict")
    manifest = app_sources["workspace_manifest"].decode("utf-8", "strict")
    anchor_config = app_sources["anchor_config"].decode("utf-8", "strict")
    require("# ResQ Programs" in readme and "built on Solana" in readme,
            "pinned application identity no longer describes a Solana program")
    require(all(f'"{member}"' in manifest for member in app["workspace_members"]),
            "pinned Cargo workspace members changed")
    require('anchor-lang = { version = "1.0.0-rc.4"' in manifest,
            "pinned workspace anchor-lang requirement changed")
    require("[programs.devnet]" in anchor_config and "resq_delivery" in anchor_config,
            "pinned Anchor application configuration changed")

    lock_package = _cargo_lock_package(app_sources["resolved_lockfile"], app["package"])
    version = lock_package["version"]
    require(version == app["resolved_version"], "Cargo.lock resolved version changed")

    advisory_db = protocol["advisory_database"]
    advisory_sources = {}
    for advisory in advisory_db["advisories"]:
        spec = _source_spec(
            advisory_db["repository"],
            advisory_db["commit"],
            {"key": advisory["id"], "path": advisory["path"], "blob": advisory["blob"]},
        )
        raw = source_bytes(spec) if fetcher is None else fetcher(spec)
        introduced, fixed = _rustsec_interval(raw, advisory["id"], app["package"])
        require(introduced == advisory["introduced"] and fixed == advisory["fixed"],
                "frozen RustSec range differs from its pinned source")
        advisory_sources[advisory["id"]] = {
            "introduced": introduced,
            "fixed": fixed,
            "reference": advisory["reference"],
            "ghsa": advisory["ghsa"],
            "source_blob": advisory["blob"],
        }

    rows = []
    for case in protocol["selection"]["cases"]:
        require(case["package"] == app["package"] and case["version"] == version,
                "frozen case no longer matches the real lockfile package")
        advisory = advisory_sources[case["advisory"]]
        candidate = _candidate_status(version, advisory["introduced"], advisory["fixed"])
        reference = _node_reference_status(version, advisory["introduced"], advisory["fixed"])
        require(reference == case["reference_status"],
                "independent SemVer reference differs from the precommitted protocol")
        rows.append({
            "case_id": case["id"],
            "package": app["package"],
            "version": version,
            "advisory": case["advisory"],
            "ghsa": advisory["ghsa"],
            "affected_interval": {
                "introduced_inclusive": advisory["introduced"],
                "fixed_exclusive": advisory["fixed"],
            },
            "citation_only_baseline": APPLICABLE,
            "semver_7_8_6_reference": reference,
            "falsum_candidate": candidate,
        })

    false_accept = sum(
        row["falsum_candidate"] == APPLICABLE
        and row["semver_7_8_6_reference"] == INAPPLICABLE
        for row in rows
    )
    false_reject = sum(
        row["falsum_candidate"] == INAPPLICABLE
        and row["semver_7_8_6_reference"] == APPLICABLE
        for row in rows
    )
    return {
        "status": "PHASE5BU_RESQ_SOLANA_LOCKFILE_COMPATIBILITY",
        "application": {
            "repository": app["repository"],
            "commit": app["commit"],
            "lockfile_path": "Cargo.lock",
            "lockfile_git_blob": next(s["blob"] for s in app["sources"] if s["key"] == "resolved_lockfile"),
            "package": app["package"],
            "resolved_version": version,
            "workspace_members": app["workspace_members"],
        },
        "advisory_database": {
            "repository": advisory_db["repository"],
            "commit": advisory_db["commit"],
            "advisories": [
                {
                    "id": advisory["id"],
                    "ghsa": advisory["ghsa"],
                    "source_blob": advisory["blob"],
                    "reference": advisory["reference"],
                }
                for advisory in advisory_db["advisories"]
            ],
        },
        "sample_sizes": {
            "applications": 1,
            "locked_package_versions": 1,
            "package_advisory_pairs": len(rows),
            "advisory_sources": len(advisory_sources),
        },
        "aggregate": {
            "falsum_coverage": sum(row["falsum_candidate"] != UNKNOWN for row in rows),
            "falsum_abstentions": sum(row["falsum_candidate"] == UNKNOWN for row in rows),
            "semver_reference_coverage": sum(row["semver_7_8_6_reference"] != UNKNOWN for row in rows),
            "falsum_semver_agreement": sum(row["falsum_candidate"] == row["semver_7_8_6_reference"] for row in rows),
            "falsum_false_acceptances_vs_semver_reference": false_accept,
            "falsum_false_rejections_vs_semver_reference": false_reject,
            "citation_only_false_applicables_vs_semver_reference": sum(
                row["citation_only_baseline"] == APPLICABLE
                and row["semver_7_8_6_reference"] == INAPPLICABLE
                for row in rows
            ),
        },
        "interpretation": {
            "context_aware_baseline": "independent semver@7.8.6 interval resolver with prereleases enabled",
            "candidate": "FALSUM Python SemVer parser and source-bound RustSec interval handling",
            "reference_is_human_appsec_gold": False,
            "false_acceptance_and_rejection_are_human_gold_rates": False,
            "full_dependency_audit": False,
            "program_source_analysis": False,
            "security_clearance": False,
            "independent_application_adoption": False,
            "telegraph_network_improvement": False,
            "owner_run_compatibility_only": True,
        },
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = audit()
    with args.out.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "sample_sizes": report["sample_sizes"],
                      "aggregate": report["aggregate"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
