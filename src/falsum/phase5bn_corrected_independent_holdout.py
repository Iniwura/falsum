"""Phase 5BN: corrected independent-label security-answer holdout.

Phase 5BM is preserved as historical evidence.  This replacement freezes actual
registry versions and reference labels before the FALSUM candidate runs.  The
labels come from PyPI's ``packaging`` and npm's ``semver`` implementations; the
candidate uses FALSUM's own policy only after the reference stage completes.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import random
import re
import subprocess
from typing import Any, Callable
from urllib.request import Request, urlopen

from .phase5m_real_source_sensitive_model import ROOT
from .phase5bm_independent_balanced_holdout import falsum_status as candidate_status


STATUS = "PHASE5BN_CORRECTED_INDEPENDENT_LABEL_HOLDOUT_AUDIT"
FROZEN_STATUS = "PHASE5BN_CORRECTED_INDEPENDENT_LABEL_HOLDOUT_FROZEN"
PROTOCOL = "data/phase5bn-corrected-independent-holdout-protocol.json"
ADVISORY_COMMIT = "76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
ADVISORY_BASE = f"https://raw.githubusercontent.com/github/advisory-database/{ADVISORY_COMMIT}/"
PYPI_BASE = "https://pypi.org/pypi/"
NPM_BASE = "https://registry.npmjs.org/"
MAX_BYTES = 8_000_000
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "UNKNOWN_OR_INSUFFICIENT"
VERSION = re.compile(r"^(?:0|[0-9]+(?:\.[0-9]+){0,3})$")
SHUFFLE_SEED = 2026112701
LEAKAGE_PERMUTATIONS = 20_000
LEAKAGE_ALPHA = 0.01
TOKEN_NAMES = ("ref-rhea", "ref-sable")

RECORDS = {
    "GHSA-8fvv-fgr5-f8ch": ("PyPI", "pymongo", "advisories/github-reviewed/2026/10/GHSA-8fvv-fgr5-f8ch/GHSA-8fvv-fgr5-f8ch.json", "14a961c57c2ae60babd99fc394592467f3a8c73c22deb2dede7753526ed38ea1"),
    "GHSA-98qm-wvgf-w4cf": ("PyPI", "pymongo", "advisories/github-reviewed/2026/10/GHSA-98qm-wvgf-w4cf/GHSA-98qm-wvgf-w4cf.json", "dd5b7faa0344602f119a22536f7a2c31cd2da4b998529e4ea550cc868d60fa17"),
    "GHSA-27x4-j476-jp5f": ("PyPI", "setuptools", "advisories/github-reviewed/2022/05/GHSA-27x4-j476-jp5f/GHSA-27x4-j476-jp5f.json", "751cba3a453eb1f60729a51d7ba0d8aaa27c09195c3994f81185763d4e2f0632"),
    "GHSA-5rjg-fvgr-3xxf": ("PyPI", "setuptools", "advisories/github-reviewed/2025/05/GHSA-5rjg-fvgr-3xxf/GHSA-5rjg-fvgr-3xxf.json", "40a19376a8a1ba8ec5ff9d3ab0f279f7bb13cdbcb2bdfe5aefc3df273ab22490"),
    "GHSA-39hc-v87j-747x": ("PyPI", "cryptography", "advisories/github-reviewed/2022/11/GHSA-39hc-v87j-747x/GHSA-39hc-v87j-747x.json", "37a0530bc92bc6d5a8536324d25f4e16a57d66d4581c11e38d4a6611944440dd"),
    "GHSA-3ww4-gg4f-jr7f": ("PyPI", "cryptography", "advisories/github-reviewed/2024/02/GHSA-3ww4-gg4f-jr7f/GHSA-3ww4-gg4f-jr7f.json", "c5d8733879d126ca46a543176d254dc9aa7c24e9b562f6c263afbbe84a236626"),
    "GHSA-r683-j2x4-v87g": ("npm", "node-fetch", "advisories/github-reviewed/2022/01/GHSA-r683-j2x4-v87g/GHSA-r683-j2x4-v87g.json", "c2d62792518f2ff73c7ea1eba4c25ae80e97a3f120291f8b0d0012c75ba31df5"),
    "GHSA-vp56-6g26-6827": ("npm", "node-fetch", "advisories/github-reviewed/2022/08/GHSA-vp56-6g26-6827/GHSA-vp56-6g26-6827.json", "1367c6832699db308e29eb0c87af5b2e330b3abd9bde4d675b755034705afb98"),
    "GHSA-23hp-3jrh-7fpw": ("npm", "tar", "advisories/github-reviewed/2026/07/GHSA-23hp-3jrh-7fpw/GHSA-23hp-3jrh-7fpw.json", "be05813e293e483855db2cd0400f96f7d5bc4ef5a27dc00d4c631dceaae737ca"),
    "GHSA-29xp-372q-xqph": ("npm", "tar", "advisories/github-reviewed/2025/10/GHSA-29xp-372q-xqph/GHSA-29xp-372q-xqph.json", "6be7751d75e76af22c2c6c340679548905e445953c83444f4e3878b01ce09e56"),
    "GHSA-g7q5-pjjr-gqvp": ("npm", "tough-cookie", "advisories/github-reviewed/2018/07/GHSA-g7q5-pjjr-gqvp/GHSA-g7q5-pjjr-gqvp.json", "44b7197a122f65846b373f690ed0c1bdb8637a4f66dfe872c761c860a7e0bb3f"),
    "GHSA-qhv9-728r-6jqg": ("npm", "tough-cookie", "advisories/github-reviewed/2018/10/GHSA-qhv9-728r-6jqg/GHSA-qhv9-728r-6jqg.json", "c3d336bdf236db3f982e18d5e72df422c4873975320e4b3efd8ea12fea72a2d1"),
}


class CorrectedHoldoutError(ValueError):
    """Raised when the independent-label contract cannot be verified."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise CorrectedHoldoutError(message)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        need(key not in output, "duplicate JSON key")
        output[key] = value
    return output


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorrectedHoldoutError("malformed JSON evidence") from exc


def _fetch(url: str) -> bytes:
    allowed = url.startswith(ADVISORY_BASE) or url.startswith(PYPI_BASE) or url.startswith(NPM_BASE)
    need(allowed, "unapproved external source URL")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "FALSUM-phase5bn/1.0"})
    with urlopen(request, timeout=40) as response:
        need(response.status == 200 and response.geturl() == url, "external source unavailable or redirected")
        raw = response.read(MAX_BYTES + 1)
    need(0 < len(raw) <= MAX_BYTES, "external source exceeds byte cap")
    return raw


def _source_url(identifier: str) -> str:
    return ADVISORY_BASE + RECORDS[identifier][2]


def _metadata_url(ecosystem: str, package: str) -> str:
    return f"{PYPI_BASE}{package}/json" if ecosystem == "PyPI" else NPM_BASE + package


def _load_external_libraries() -> tuple[Any, Any]:
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError as exc:
        raise CorrectedHoldoutError("install packaging==26.4 for the external PyPI resolver") from exc
    node = os.environ.get("FALSUM_PHASE5BN_NODE_PATH")
    need(node, "FALSUM_PHASE5BN_NODE_PATH must point to semver@7.8.6 node_modules")
    probe = subprocess.run(
        ["node", "-e", "const s=require('semver'); process.stdout.write(s.version || '7.x')"],
        text=True, capture_output=True, env={**os.environ, "NODE_PATH": node}, check=False,
    )
    need(probe.returncode == 0 and probe.stdout.strip().startswith("7."), "semver@7.x external resolver unavailable")
    return (SpecifierSet, Version, InvalidVersion)


def _matching_events(advisory: dict[str, Any], ecosystem: str, package: str) -> list[list[dict[str, str]]]:
    matches: list[list[dict[str, str]]] = []
    for affected in advisory.get("affected", []):
        if not isinstance(affected, dict):
            continue
        record = affected.get("package")
        if not isinstance(record, dict) or record.get("ecosystem") != ecosystem or record.get("name") != package:
            continue
        for version_range in affected.get("ranges", []):
            if isinstance(version_range, dict) and version_range.get("type") in ("ECOSYSTEM", "SEMVER"):
                events = version_range.get("events")
                if isinstance(events, list):
                    matches.append(events)
    return matches


def _range_expression(events: list[dict[str, str]]) -> str | None:
    parts: list[str] = []
    opened: str | None = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return None
        key, value = next(iter(event.items()))
        if not isinstance(value, str) or not VERSION.fullmatch(value):
            return None
        if key == "introduced" and opened is None:
            opened = value
        elif key in ("fixed", "last_affected") and opened is not None:
            parts.append(f">={opened}")
            parts.append(("<" if key == "fixed" else "<=") + value)
            opened = None
        else:
            return None
    if opened is not None:
        parts.append(f">={opened}")
    return " ".join(parts) if parts else None


def _npm_statuses(versions: list[str], ranges: list[str]) -> list[bool]:
    node_path = os.environ.get("FALSUM_PHASE5BN_NODE_PATH")
    need(node_path, "FALSUM_PHASE5BN_NODE_PATH is missing")
    script = """
const semver = require('semver');
let raw=''; process.stdin.on('data', c => raw += c);
process.stdin.on('end', () => {
  const input=JSON.parse(raw);
  const output=input.versions.map(v => input.ranges.some(r => semver.satisfies(v, r, {includePrerelease:true})));
  process.stdout.write(JSON.stringify(output));
});
"""
    proc = subprocess.run(
        ["node", "-e", script], input=json.dumps({"versions": versions, "ranges": ranges}),
        text=True, capture_output=True, env={**os.environ, "NODE_PATH": node_path}, check=False,
    )
    need(proc.returncode == 0, "semver resolver failed")
    output = strict_json(proc.stdout.encode("utf-8"))
    need(isinstance(output, list) and len(output) == len(versions) and all(isinstance(x, bool) for x in output), "invalid semver resolver output")
    return output


def _pypi_statuses(versions: list[str], ranges: list[str]) -> list[bool]:
    SpecifierSet, Version, InvalidVersion = _load_external_libraries()
    specs = [SpecifierSet(expr.replace(" ", ",")) for expr in ranges]
    output: list[bool] = []
    for value in versions:
        try:
            parsed = Version(value)
        except InvalidVersion:
            output.append(False)
            continue
        output.append(any(spec.contains(parsed, prereleases=True) for spec in specs))
    return output


def _external_statuses(advisory: dict[str, Any], ecosystem: str, package: str,
                       versions: list[str]) -> list[str]:
    if advisory.get("withdrawn") or not advisory.get("database_specific", {}).get("github_reviewed"):
        return [UNKNOWN] * len(versions)
    ranges = [_range_expression(events) for events in _matching_events(advisory, ecosystem, package)]
    ranges = [value for value in ranges if value]
    if not ranges:
        return [INAPPLICABLE] * len(versions)
    matched = _npm_statuses(versions, ranges) if ecosystem == "npm" else _pypi_statuses(versions, ranges)
    return [APPLICABLE if flag else INAPPLICABLE for flag in matched]


def _sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    if ecosystem == "PyPI":
        _, Version, InvalidVersion = _load_external_libraries()
        try:
            return sorted(versions, key=Version)
        except InvalidVersion as exc:
            raise CorrectedHoldoutError("invalid PyPI version in registry metadata") from exc
    node_path = os.environ.get("FALSUM_PHASE5BN_NODE_PATH")
    script = "const s=require('semver'); let x=''; process.stdin.on('data',c=>x+=c); process.stdin.on('end',()=>process.stdout.write(JSON.stringify(s.sort(JSON.parse(x)))));"
    proc = subprocess.run(["node", "-e", script], input=json.dumps(versions), text=True,
                          capture_output=True, env={**os.environ, "NODE_PATH": node_path or ""}, check=False)
    need(proc.returncode == 0, "semver sort failed")
    output = strict_json(proc.stdout.encode("utf-8"))
    need(isinstance(output, list) and len(output) == len(versions), "invalid semver sort output")
    return [str(value) for value in output]


def _available_versions(ecosystem: str, metadata: dict[str, Any]) -> list[str]:
    if ecosystem == "PyPI":
        releases = metadata.get("releases")
        need(isinstance(releases, dict), "PyPI metadata has no releases map")
        values = list(releases)
    else:
        versions = metadata.get("versions")
        need(isinstance(versions, dict), "npm metadata has no versions map")
        values = list(versions)
    return _sort_versions(ecosystem, [str(value) for value in values if isinstance(value, str)])


def _meaningful_answer(ecosystem: str, package: str, version: str, identifier: str, role: str) -> dict[str, str]:
    target = f"{ecosystem}:{package}@{version}"
    if role == APPLICABLE:
        text = (f"For {target}, advisory {identifier} is inside the published affected range. "
                "Treat this dependency as affected for this review, block the release or upgrade "
                "before relying on it. This is version applicability only, not exploitability.")
        action = "block_or_upgrade"
    else:
        text = (f"For {target}, advisory {identifier} is outside the published affected range. "
                "Do not attribute this advisory to the dependency, and do not require an upgrade "
                "for this record. This is version applicability only, not exploitability.")
        action = "no_action_for_this_record"
    return {"text": text, "action": action, "scope": "version_applicability_only"}


def _assemble_cases(raw_cases: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    shuffled = list(raw_cases)
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    cases: list[dict[str, Any]] = []
    for index, raw in enumerate(shuffled):
        applicable_token, inapplicable_token = rng.sample(list(TOKEN_NAMES), 2)
        ref_token = applicable_token if raw["reference_label"] == APPLICABLE else inapplicable_token
        options = [
            {"answer_token": applicable_token, **_meaningful_answer(raw["ecosystem"], raw["package"], raw["version"], raw["advisory_id"], APPLICABLE)},
            {"answer_token": inapplicable_token, **_meaningful_answer(raw["ecosystem"], raw["package"], raw["version"], raw["advisory_id"], INAPPLICABLE)},
        ]
        rng.shuffle(options)
        cases.append({
            "case_id": hashlib.sha256(f"{raw['advisory_id']}|{raw['ecosystem']}|{raw['package']}|{raw['version']}".encode()).hexdigest()[:16],
            "case_index": index,
            "advisory_id": raw["advisory_id"],
            "target": {"ecosystem": raw["ecosystem"], "package": raw["package"], "version": raw["version"]},
            "options": options,
            "reference": {"label": raw["reference_label"], "correct_answer_token": ref_token,
                          "applicable_answer_token": applicable_token, "inapplicable_answer_token": inapplicable_token},
        })
    return cases


def _build_protocol(root: Path = ROOT) -> dict[str, Any]:
    _load_external_libraries()
    records: list[dict[str, Any]] = []
    raw_cases: list[dict[str, Any]] = []
    for identifier, (ecosystem, package, path, digest) in RECORDS.items():
        advisory_raw = _fetch(_source_url(identifier))
        need(hashlib.sha256(advisory_raw).hexdigest() == digest, f"advisory changed: {identifier}")
        advisory = strict_json(advisory_raw)
        need(isinstance(advisory, dict), "advisory is not an object")
        metadata_raw = _fetch(_metadata_url(ecosystem, package))
        metadata_digest = hashlib.sha256(metadata_raw).hexdigest()
        metadata = strict_json(metadata_raw)
        need(isinstance(metadata, dict), "package metadata is not an object")
        versions = _available_versions(ecosystem, metadata)
        statuses = _external_statuses(advisory, ecosystem, package, versions)
        vulnerable = [version for version, status in zip(versions, statuses) if status == APPLICABLE]
        safe = [version for version, status in zip(versions, statuses) if status == INAPPLICABLE]
        need(vulnerable and safe, f"no existing vulnerable/fixed version pair: {package}")
        affected_version, fixed_version = vulnerable[-1], safe[0]
        records.append({
            "id": identifier, "ecosystem": ecosystem, "package": package, "advisory_path": path,
            "advisory_sha256": digest, "metadata_url": _metadata_url(ecosystem, package),
            "metadata_sha256": metadata_digest,
            "verified_versions": [affected_version, fixed_version],
        })
        raw_cases.extend([
            {"advisory_id": identifier, "ecosystem": ecosystem, "package": package,
             "version": affected_version, "reference_label": APPLICABLE},
            {"advisory_id": identifier, "ecosystem": ecosystem, "package": package,
             "version": fixed_version, "reference_label": INAPPLICABLE},
        ])

    need(Counter(case["reference_label"] for case in raw_cases) == Counter({APPLICABLE: 12, INAPPLICABLE: 12}), "reference labels are not balanced")
    # This seed is fixed before candidate execution.  It is not searched against
    # the external labels: doing so would make the holdout layout outcome-selected.
    cases = _assemble_cases(raw_cases, SHUFFLE_SEED)
    return {
        "schema_version": 2,
        "status": FROZEN_STATUS,
        "frozen_date_utc": datetime.now(timezone.utc).date().isoformat(),
        "intent": "SECURITY_REVIEW_GENERAL",
        "family": "SECURITY_REVIEW",
        "dataset": {"advisory_repository": "github/advisory-database", "advisory_commit": ADVISORY_COMMIT,
                    "external_resolvers": {"PyPI": "packaging==26.4", "npm": "semver@7.8.6"},
                    "label_stage": "Reference labels were derived from external resolvers and frozen before candidate execution."},
        "selection": {"package_roster_frozen_before_advisory_fetch": True,
                       "outcome_based_reselection": False,
                       "case_shuffle_seed": SHUFFLE_SEED,
                       "answer_token_assignment_seed_continues_after_case_shuffle": True,
                       "layout_seed_selected_without_reference_labels": True},
        "records": records,
        "cases": cases,
        "contract": {
            "candidate_policy": "FALSUM runs only after independent reference labels and registry existence checks pass.",
            "meaningful_answers": "Each option is a target-specific security triage answer with evidence scope and action, not an A/B placeholder.",
            "leakage_features_to_measure": ["case_index_parity", "case_index_mod_3", "answer_position", "answer_token"],
            "no_human_gold_claim": True,
        },
    }


def _load_protocol(root: Path = ROOT) -> dict[str, Any]:
    protocol = strict_json((root / PROTOCOL).read_bytes())
    need(isinstance(protocol, dict) and protocol.get("schema_version") == 2
         and protocol.get("status") == FROZEN_STATUS, "invalid corrected protocol")
    cases = protocol.get("cases")
    need(isinstance(cases, list) and len(cases) == 24, "corrected case roster changed")
    need(len({case.get("case_id") for case in cases if isinstance(case, dict)}) == 24, "case IDs are not unique")
    return protocol


def _verify_frozen_versions_present(record: dict[str, Any], metadata: dict[str, Any]) -> None:
    """Verify the preselected package versions without pinning a mutable index document.

    PyPI and npm package-level metadata endpoints change whenever a new release
    is published or registry metadata is refreshed. The protocol's metadata
    SHA-256 remains the freeze-time snapshot identity. Requiring the current
    full document to retain that hash makes an immutable 24-case roster fail
    merely because an unrelated release was added. Replay therefore checks
    only that each already-frozen version key remains present. Advisory bytes,
    version strings, reference labels, case order and answer surfaces remain
    frozen; no new version is selected and no label is recomputed from a new
    registry release.
    """
    ecosystem = record.get("ecosystem")
    package = record.get("package")
    frozen = record.get("verified_versions")
    need(ecosystem in ("PyPI", "npm"), "unsupported registry ecosystem")
    need(isinstance(package, str) and package, "package identity is missing")
    snapshot_digest = record.get("metadata_sha256")
    need(isinstance(snapshot_digest, str) and re.fullmatch(r"[0-9a-f]{64}", snapshot_digest) is not None,
         "freeze-time registry metadata digest is malformed")
    need(isinstance(frozen, list) and len(frozen) == 2
         and all(isinstance(version, str) and version for version in frozen)
         and len(set(frozen)) == 2, "frozen package-version pair is malformed")
    if ecosystem == "npm":
        need(metadata.get("name") == package, "npm metadata package identity changed")
    else:
        info = metadata.get("info")
        need(isinstance(info, dict) and info.get("name") == package,
             "PyPI metadata package identity changed")
    key = "releases" if ecosystem == "PyPI" else "versions"
    version_map = metadata.get(key)
    need(isinstance(version_map, dict), f"{ecosystem} metadata has no {key} map")
    available = {version for version in version_map if isinstance(version, str)}
    for version in frozen:
        need(version in available, f"claimed package version no longer exists: {package}@{version}")


def _load_sources_and_metadata(protocol: dict[str, Any], fetcher: Callable[[str], bytes] = _fetch) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    sources: dict[str, dict[str, Any]] = {}
    metadata: dict[str, dict[str, Any]] = {}
    for record in protocol["records"]:
        identifier = record["id"]
        advisory_raw = fetcher(_source_url(identifier))
        need(hashlib.sha256(advisory_raw).hexdigest() == record["advisory_sha256"], f"advisory tampered: {identifier}")
        advisory = strict_json(advisory_raw)
        need(isinstance(advisory, dict) and advisory.get("id") == identifier, f"advisory identity changed: {identifier}")
        metadata_raw = fetcher(record["metadata_url"])
        package_metadata = strict_json(metadata_raw)
        need(isinstance(package_metadata, dict), "package metadata malformed")
        _verify_frozen_versions_present(record, package_metadata)
        sources[identifier] = advisory
        metadata[record["package"]] = package_metadata
    return sources, metadata


def _reference_stage(protocol: dict[str, Any], sources: dict[str, dict[str, Any]]) -> dict[str, str]:
    labels: dict[str, str] = {}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in protocol["cases"]:
        grouped[case["advisory_id"]].append(case)
    for identifier, cases in grouped.items():
        record = next(row for row in protocol["records"] if row["id"] == identifier)
        versions = [case["target"]["version"] for case in cases]
        actual = _external_statuses(sources[identifier], record["ecosystem"], record["package"], versions)
        for case, label in zip(cases, actual):
            need(label == case["reference"]["label"], f"independent reference label changed: {case['case_id']}")
            labels[case["case_id"]] = label
    return labels


def _bucket_accuracy(labels: list[str], feature_buckets: list[str]) -> dict[str, Any]:
    need(len(labels) == len(feature_buckets) and labels, "leakage input is empty or misaligned")
    buckets: dict[str, list[str]] = defaultdict(list)
    for label, bucket in zip(labels, feature_buckets):
        buckets[bucket].append(label)
    correct = 0
    mapping: dict[str, str] = {}
    for key, bucket_labels in buckets.items():
        counts = Counter(bucket_labels)
        winner = sorted(counts, key=lambda label: (-counts[label], label))[0]
        mapping[key] = winner
        correct += counts[winner]
    return {"correct": correct, "denominator": len(labels), "bucket_majority": mapping}


def _permutation_p_value(labels: list[str], buckets: list[str], observed: int,
                         feature_name: str) -> float:
    """Estimate a fixed, predeclared permutation p-value for feature leakage."""
    rng = random.Random(f"{SHUFFLE_SEED}:{feature_name}:label-permutation")
    shuffled = list(labels)
    at_least_observed = 0
    for _ in range(LEAKAGE_PERMUTATIONS):
        rng.shuffle(shuffled)
        if _bucket_accuracy(shuffled, buckets)["correct"] >= observed:
            at_least_observed += 1
    return (at_least_observed + 1) / (LEAKAGE_PERMUTATIONS + 1)


def _leakage_audit(cases: list[dict[str, Any]]) -> dict[str, Any]:
    labels = [case["reference"]["label"] for case in cases]
    features = {
        "case_index_parity": [str(case["case_index"] % 2) for case in cases],
        "case_index_mod_3": [str(case["case_index"] % 3) for case in cases],
        "answer_position": [str(next(i for i, option in enumerate(case["options"])
                                    if option["answer_token"] == case["reference"]["correct_answer_token"]))
                             for case in cases],
        "answer_token": [case["reference"]["correct_answer_token"] for case in cases],
    }
    baseline = max(Counter(labels).values()) / len(labels)
    metrics: dict[str, dict[str, Any]] = {}
    for name, buckets in features.items():
        summary = _bucket_accuracy(labels, buckets)
        p_value = _permutation_p_value(labels, buckets, summary["correct"], name)
        metrics[name] = {
            **summary,
            "observed_accuracy": summary["correct"] / summary["denominator"],
            "baseline_accuracy": baseline,
            "excess_over_baseline": summary["correct"] / summary["denominator"] - baseline,
            "permutation_p_value": p_value,
        }
    leakage = any(metric["permutation_p_value"] < LEAKAGE_ALPHA
                  and metric["excess_over_baseline"] > 0 for metric in metrics.values())
    return {"metrics": metrics, "label_leakage_detected": leakage}


def audit(root: Path = ROOT, fetcher: Callable[[str], bytes] = _fetch) -> dict[str, Any]:
    _load_external_libraries()
    protocol = _load_protocol(root)
    sources, metadata = _load_sources_and_metadata(protocol, fetcher)
    # This completes before any candidate policy call below.
    reference_labels = _reference_stage(protocol, sources)
    cases: list[dict[str, Any]] = []
    for frozen in protocol["cases"]:
        advisory = sources[frozen["advisory_id"]]
        target = frozen["target"]
        candidate = candidate_status(advisory, target)
        ref_label = reference_labels[frozen["case_id"]]
        correct_token = frozen["reference"]["correct_answer_token"]
        selected_token = (frozen["reference"]["applicable_answer_token"]
                          if candidate == APPLICABLE
                          else frozen["reference"]["inapplicable_answer_token"]
                          if candidate == INAPPLICABLE else None)
        cases.append({
            "case_id": frozen["case_id"], "case_index": frozen["case_index"], "target": target,
            "options": frozen["options"], "reference_label": ref_label,
            "falsum_decision": candidate, "falsum_correct": candidate == ref_label,
            "falsum_selected_answer_token": selected_token,
            "falsum_answer_correct": selected_token == correct_token,
        })
    leakage = _leakage_audit(protocol["cases"])
    answer_lengths = [len(option["text"]) for case in protocol["cases"] for option in case["options"]]
    need(all(isinstance(option.get("text"), str) and len(option["text"]) >= 120
             and isinstance(option.get("action"), str)
             and option.get("scope") == "version_applicability_only"
             for case in protocol["cases"] for option in case["options"]), "placeholder answer surface detected")
    falsum_correct = sum(row["falsum_correct"] for row in cases)
    answer_correct = sum(row["falsum_answer_correct"] for row in cases)
    return {
        "schema_version": 1, "status": STATUS, "protocol": PROTOCOL,
        "reference_stage_completed_before_candidate": True,
        "frozen_package_versions_verified_against_live_registry": True,
        "registry_metadata_policy": {
            "freeze_time_snapshot_hashes_retained": True,
            "full_mutable_metadata_digest_rechecked": False,
            "replay_check": "all preselected version keys remain present; no new versions are selected",
        },
        "registry_metadata_snapshots": [
            {
                "ecosystem": record["ecosystem"],
                "package": record["package"],
                "freeze_time_sha256": record["metadata_sha256"],
                "frozen_versions": record["verified_versions"],
            }
            for record in protocol["records"]
        ],
        "cases": cases,
        "balance": {"total": 24, "applicable": sum(row["reference_label"] == APPLICABLE for row in cases),
                    "inapplicable": sum(row["reference_label"] == INAPPLICABLE for row in cases),
                    "package_families": 6, "ecosystems": {"PyPI": 12, "npm": 12}},
        "policies": {
            "falsum": {"correct": falsum_correct, "incorrect": 24 - falsum_correct, "denominator": 24},
            "external_resolver_reference": {"correct": 24, "incorrect": 0, "denominator": 24},
            "falsum_answer_selection": {"correct": answer_correct, "incorrect": 24 - answer_correct, "denominator": 24},
        },
        "answer_surface_audit": {"meaningful_competing_answers": True,
                                  "minimum_option_text_length": min(answer_lengths),
                                  "distinct_option_texts": len({option["text"] for case in protocol["cases"] for option in case["options"]}),
                                  "placeholder_a_or_b_only": False},
        "leakage_audit": leakage,
        "interpretation": {
            "meaningful_quality_discrimination": falsum_correct < 24,
            "live_registry_metadata_is_mutable": True,
            "freeze_time_metadata_hash_is_provenance_not_live_document_equality": True,
            "falsum_beats_external_resolver": False,
            "independent_human_appsec_gold": False,
            "security_clearance": False, "ranking_improvement": False,
            "new_paid_telegraph_execution": False,
            "summary": "The corrected holdout freezes independently resolved registry versions and labels before FALSUM execution, tests index/token leakage, and evaluates target-specific competing security answers. It is version-applicability evidence, not human AppSec gold.",
        },
        "limits": [
            "External resolver agreement is a competent version-resolution baseline, not human semantic AppSec adjudication.",
            "The answer surfaces are meaningful source-bound triage alternatives, but the experiment does not establish exploitability or customer adoption.",
        ],
    }


def _write_once(path: Path, payload: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "output must be a new JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--freeze", action="store_true")
    args = parser.parse_args(argv)
    try:
        payload = _build_protocol() if args.freeze else audit()
        _write_once(args.out, payload)
        print(json.dumps({"status": payload["status"], "cases": len(payload.get("cases", [])),
                          "falsum_correct": payload.get("policies", {}).get("falsum", {}).get("correct"),
                          "external_reference_correct": payload.get("policies", {}).get("external_resolver_reference", {}).get("correct"),
                          "label_leakage_detected": payload.get("leakage_audit", {}).get("label_leakage_detected")}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        parser.exit(1, "PHASE5BN CORRECTED HOLDOUT FAILED CLOSED: " + str(exc)[:400] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
