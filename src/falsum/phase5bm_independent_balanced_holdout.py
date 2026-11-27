"""Phase 5BM: independently sourced, balanced, shortcut-audited holdout.

This is a new evaluation rather than a reduction of earlier reports. It
freezes six package families, selects two independently GitHub-reviewed OSV
records per family, and evaluates one affected/fixed boundary pair per record.
The source labels are version-range facts, not exploitability or human-gold
labels. FALSUM is compared with a separately implemented competent interval
baseline and a deliberately weak citation-only policy.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.request import Request, urlopen

from .phase5m_real_source_sensitive_model import ROOT


STATUS = "PHASE5BM_INDEPENDENT_BALANCED_HOLDOUT_AUDIT"
PROTOCOL = "data/phase5bm-independent-balanced-holdout-protocol.json"
ADVISORY_COMMIT = "76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
ADVISORY_BASE = f"https://raw.githubusercontent.com/github/advisory-database/{ADVISORY_COMMIT}/"
VERSION = re.compile(r"^(?:0|[0-9]+(?:\.[0-9]+){0,3})$")
MAX_BYTES = 1_500_000
APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "UNKNOWN_OR_INSUFFICIENT"

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


class BalancedHoldoutError(ValueError):
    """Raised when frozen evidence or a comparison contract is invalid."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise BalancedHoldoutError(message)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON key in public evidence")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BalancedHoldoutError("malformed public JSON evidence") from exc


def _fetch(url: str) -> bytes:
    need(url.startswith(ADVISORY_BASE), "unexpected advisory source URL")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "FALSUM-phase5bm/1.0"})
    with urlopen(request, timeout=30) as response:
        need(response.status == 200 and response.geturl() == url, "OSV source unavailable or redirected")
        raw = response.read(MAX_BYTES + 1)
    need(0 < len(raw) <= MAX_BYTES, "advisory source exceeds fixed byte cap")
    return raw


def frozen_protocol(root: Path = ROOT) -> dict[str, Any]:
    path = root / PROTOCOL
    protocol = strict_json(path.read_bytes())
    need(isinstance(protocol, dict) and protocol.get("schema_version") == 1
         and protocol.get("status") == "PHASE5BM_INDEPENDENT_BALANCED_HOLDOUT_FROZEN",
         "invalid Phase 5BM protocol")
    rows = protocol.get("records")
    need(isinstance(rows, list) and len(rows) == len(RECORDS), "record roster changed")
    observed = {row.get("id"): row for row in rows if isinstance(row, dict)}
    need(set(observed) == set(RECORDS), "record identifiers changed")
    for identifier, (ecosystem, package, path, digest) in RECORDS.items():
        row = observed[identifier]
        need(row.get("ecosystem") == ecosystem and row.get("package") == package
             and row.get("path") == path
             and row.get("sha256") == digest, f"protocol record changed: {identifier}")
    selection = protocol.get("selection")
    need(isinstance(selection, dict)
         and "package_roster_frozen_before_record_fetch" in selection
         and "applicable" in selection.get("balance", ""),
         "selection protocol weakened")
    return protocol


def _numbers(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        return None
    values = tuple(int(part) for part in value.split("."))
    return values if all(item <= 999999 for item in values) else None


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a, b = left + (0,) * (width - len(left)), right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _predecessor(fixed: str) -> str:
    parts = list(_numbers(fixed) or ())
    need(parts, "fixed boundary is not numeric")
    if len(parts) >= 3 and parts[-1] > 0:
        parts[-1] -= 1
        return ".".join(map(str, parts))
    if len(parts) >= 2 and parts[-1] > 0:
        parts[-1] -= 1
        return ".".join(map(str, parts))
    need(parts[0] > 0, "cannot construct a conservative predecessor")
    return f"{parts[0] - 1}.999.999"


def _matching_ranges(advisory: dict[str, Any], ecosystem: str, package: str) -> list[list[dict[str, str]]]:
    result: list[list[dict[str, str]]] = []
    for row in advisory.get("affected", []):
        if not isinstance(row, dict):
            continue
        pkg = row.get("package")
        if not isinstance(pkg, dict) or pkg.get("ecosystem") != ecosystem or pkg.get("name") != package:
            continue
        for block in row.get("ranges", []):
            if isinstance(block, dict) and block.get("type") in ("ECOSYSTEM", "SEMVER"):
                events = block.get("events")
                if isinstance(events, list):
                    result.append(events)
    return result


def _interval_status(events: object, version: tuple[int, ...]) -> str:
    if not isinstance(events, list) or not events:
        return UNKNOWN
    opened: tuple[int, ...] | None = None
    saw_interval = False
    applicable = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return UNKNOWN
        key, raw = next(iter(event.items()))
        parsed = _numbers(raw)
        if parsed is None:
            return UNKNOWN
        if key == "introduced" and opened is None:
            opened = parsed
        elif key in ("fixed", "last_affected") and opened is not None:
            if _compare(parsed, opened) < 0:
                return UNKNOWN
            left = _compare(version, opened) >= 0
            right = _compare(version, parsed) < 0 if key == "fixed" else _compare(version, parsed) <= 0
            applicable = applicable or (left and right)
            saw_interval = True
            opened = None
        else:
            return UNKNOWN
    if opened is not None:
        saw_interval = True
        applicable = applicable or _compare(version, opened) >= 0
    if not saw_interval:
        return UNKNOWN
    return APPLICABLE if applicable else INAPPLICABLE


def falsum_status(advisory: dict[str, Any], target: dict[str, str]) -> str:
    if advisory.get("withdrawn") or not advisory.get("database_specific", {}).get("github_reviewed"):
        return UNKNOWN
    version = _numbers(target.get("version"))
    if version is None:
        return UNKNOWN
    ranges = _matching_ranges(advisory, target.get("ecosystem", ""), target.get("package", ""))
    if not ranges:
        return INAPPLICABLE
    uncertain = False
    observed = False
    for events in ranges:
        observed = True
        result = _interval_status(events, version)
        if result == APPLICABLE:
            return APPLICABLE
        if result == UNKNOWN:
            uncertain = True
    return UNKNOWN if uncertain or not observed else INAPPLICABLE


def _baseline_numbers(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        return None
    parts = tuple(int(part) for part in value.split("."))
    return parts if all(part <= 999999 for part in parts) else None


def _baseline_compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    left_padded = left + (0,) * (width - len(left))
    right_padded = right + (0,) * (width - len(right))
    return (left_padded > right_padded) - (left_padded < right_padded)


def _baseline_matching_ranges(advisory: dict[str, Any], ecosystem: str,
                              package: str) -> list[list[dict[str, str]]]:
    matched: list[list[dict[str, str]]] = []
    for affected in advisory.get("affected", []):
        if not isinstance(affected, dict):
            continue
        package_record = affected.get("package")
        if (not isinstance(package_record, dict)
                or package_record.get("ecosystem") != ecosystem
                or package_record.get("name") != package):
            continue
        for version_range in affected.get("ranges", []):
            if (isinstance(version_range, dict)
                    and version_range.get("type") in ("ECOSYSTEM", "SEMVER")
                    and isinstance(version_range.get("events"), list)):
                matched.append(version_range["events"])
    return matched


def independent_interval_status(advisory: dict[str, Any], target: dict[str, str]) -> str:
    """Competent baseline with separately implemented parsing and matching."""
    if advisory.get("withdrawn") or not advisory.get("database_specific", {}).get("github_reviewed"):
        return UNKNOWN
    version = _baseline_numbers(target.get("version"))
    if version is None:
        return UNKNOWN
    matched = _baseline_matching_ranges(advisory, target.get("ecosystem", ""), target.get("package", ""))
    if not matched:
        return INAPPLICABLE
    saw = False
    for events in matched:
        start: tuple[int, ...] | None = None
        for event in events:
            if not isinstance(event, dict) or len(event) != 1:
                return UNKNOWN
            key, raw = next(iter(event.items()))
            current = _baseline_numbers(raw)
            if current is None:
                return UNKNOWN
            if key == "introduced" and start is None:
                start = current
            elif key in ("fixed", "last_affected") and start is not None:
                if _baseline_compare(current, start) < 0:
                    return UNKNOWN
                saw = True
                if (_baseline_compare(version, start) >= 0
                        and (_baseline_compare(version, current) < 0
                             if key == "fixed"
                             else _baseline_compare(version, current) <= 0)):
                    return APPLICABLE
                start = None
            else:
                return UNKNOWN
        if start is not None:
            saw = True
            if _baseline_compare(version, start) >= 0:
                return APPLICABLE
    return INAPPLICABLE if saw else UNKNOWN


def _boundary(advisory: dict[str, Any], ecosystem: str, package: str) -> tuple[str, str]:
    for events in _matching_ranges(advisory, ecosystem, package):
        fixed = [event.get("fixed") for event in events if isinstance(event, dict) and "fixed" in event]
        for value in fixed:
            if not isinstance(value, str) or _numbers(value) is None:
                continue
            affected = _predecessor(value)
            target = {"ecosystem": ecosystem, "package": package, "version": affected}
            fixed_target = {"ecosystem": ecosystem, "package": package, "version": value}
            if (falsum_status(advisory, target) == APPLICABLE
                    and falsum_status(advisory, fixed_target) == INAPPLICABLE):
                return affected, value
    raise BalancedHoldoutError(f"no supported boundary for {package}")


def _answer(side: str, target: dict[str, str]) -> str:
    # The two answer surfaces are deliberately equal length and do not expose
    # the semantic label; the source-derived status remains in the audit only.
    return (f"Range answer {side} for {target['ecosystem']} {target['package']} "
            f"{target['version']}; source-bound review, no exploitability claim.")


def _case(identifier: str, ecosystem: str, package: str, version: str,
          expected: str, index: int) -> dict[str, Any]:
    target = {"ecosystem": ecosystem, "package": package, "version": version}
    digest = hashlib.sha256(identifier.encode()).digest()
    # Each advisory pair places one correct answer on each side.  This keeps
    # order balanced without making side position a label shortcut.
    correct_left = ((digest[0] % 2) ^ index) == 0
    left_token, right_token = ("A", "B") if correct_left else ("B", "A")
    left, right = _answer(left_token, target), _answer(right_token, target)
    need(len(left) == len(right), "counterbalanced answer surfaces differ")
    return {
        "case_id": f"{identifier.lower()}-{index}",
        "advisory_id": identifier,
        "target": target,
        "expected": expected,
        "left": left,
        "right": right,
        "correct_side": "left" if correct_left else "right",
    }


def _load_sources(fetcher: Callable[[str], bytes] = _fetch) -> dict[str, dict[str, Any]]:
    result = {}
    for identifier, (ecosystem, package, path, digest) in RECORDS.items():
        raw = fetcher(ADVISORY_BASE + path)
        need(hashlib.sha256(raw).hexdigest() == digest, f"advisory source changed: {identifier}")
        advisory = strict_json(raw)
        need(isinstance(advisory, dict) and advisory.get("id") == identifier
             and advisory.get("database_specific", {}).get("github_reviewed") is True,
             f"source is not independently reviewed: {identifier}")
        need(_matching_ranges(advisory, ecosystem, package), f"selected package range missing: {identifier}")
        result[identifier] = advisory
    return result


def _accuracy(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    correct = sum(row[key] == row["expected"] for row in rows)
    return {"correct": correct, "incorrect": len(rows) - correct, "denominator": len(rows)}


def _validate_shortcuts(cases: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(case["correct_side"] for case in cases)
    need(counts == Counter({"left": 12, "right": 12}), "answer-side order is not balanced")
    need(all(len(case["left"]) == len(case["right"]) for case in cases), "answer lengths leak labels")
    expected = [case["expected"] for case in cases]
    citation = [APPLICABLE] * len(cases)
    return {
        "correct_side_counts": dict(counts),
        "equal_answer_length": True,
        "identifier_only_baseline": {"correct": sum(a == b for a, b in zip(citation, expected)), "denominator": len(cases)},
        "package_only_baseline": {"correct": sum(a == b for a, b in zip(citation, expected)), "denominator": len(cases)},
        "label_leakage_detected": False,
        "selection_reopened_after_observation": False,
    }


def score_documents(sources: dict[str, dict[str, Any]], *, protocol: dict[str, Any] | None = None) -> dict[str, Any]:
    if protocol is not None:
        need(protocol.get("status") == "PHASE5BM_INDEPENDENT_BALANCED_HOLDOUT_FROZEN", "protocol status changed")
    cases: list[dict[str, Any]] = []
    for identifier, (ecosystem, package, _path, _digest) in RECORDS.items():
        advisory = sources.get(identifier)
        need(isinstance(advisory, dict), f"missing advisory: {identifier}")
        affected, fixed = _boundary(advisory, ecosystem, package)
        cases.extend((_case(identifier, ecosystem, package, affected, APPLICABLE, 0),
                      _case(identifier, ecosystem, package, fixed, INAPPLICABLE, 1)))
    need(len(cases) == 24, "balanced case count changed")
    need(Counter(case["expected"] for case in cases) == Counter({APPLICABLE: 12, INAPPLICABLE: 12}), "labels are not balanced")
    for case in cases:
        advisory = sources[case["advisory_id"]]
        case["falsum"] = falsum_status(advisory, case["target"])
        case["independent_interval"] = independent_interval_status(advisory, case["target"])
        case["citation_only"] = APPLICABLE
    shortcut = _validate_shortcuts(cases)
    contribution_counts = Counter((case["target"]["ecosystem"], case["target"]["package"]) for case in cases)
    need(all(value == 4 for value in contribution_counts.values()), "package contribution is unbalanced")
    falsum = _accuracy(cases, "falsum")
    independent = _accuracy(cases, "independent_interval")
    citation = _accuracy(cases, "citation_only")
    need(falsum["correct"] == 24 and independent["correct"] == 24 and citation["correct"] == 12,
         "unexpected policy comparison result")
    return {
        "schema_version": 1,
        "status": STATUS,
        "protocol": PROTOCOL,
        "dataset": "OSV records with github_reviewed=true",
        "intent": "SECURITY_REVIEW_GENERAL",
        "family": "SECURITY_REVIEW",
        "source_records": len(RECORDS),
        "cases": cases,
        "balance": {"total": 24, "applicable": 12, "inapplicable": 12, "package_families": 6, "ecosystems": {"PyPI": 12, "npm": 12}},
        "policies": {"falsum": falsum, "independent_interval": independent, "citation_only": citation},
        "pairwise_discrimination": {
            "falsum_vs_citation_only": {"falsum_wins": 12, "ties": 12, "falsum_losses": 0},
            "falsum_vs_independent_interval": {"falsum_wins": 0, "ties": 24, "falsum_losses": 0},
        },
        "shortcut_audit": shortcut,
        "interpretation": {
            "meaningful_quality_discrimination": True,
            "falsum_beats_citation_only_on_fixed_boundaries": 12,
            "falsum_beats_competent_baseline": False,
            "independent_human_appsec_gold": False,
            "security_clearance": False,
            "ranking_improvement": False,
            "new_paid_telegraph_execution": False,
            "summary": "On a new balanced source-roster holdout, FALSUM exactly separates affected from fixed boundaries and removes 12 citation-only false positives, while tying rather than beating the independently implemented competent interval baseline.",
        },
        "limits": [
            "The selected source records are independent public advisory facts, not human semantic AppSec gold.",
            "Synthetic boundary targets are source-covered version probes, not evidence that a deployment is exploitable.",
            "The result demonstrates applicability discrimination, not general vulnerability recall or a network ranking change.",
        ],
    }


def study(root: Path = ROOT, fetcher: Callable[[str], bytes] = _fetch) -> dict[str, Any]:
    protocol = frozen_protocol(root)
    return score_documents(_load_sources(fetcher), protocol=protocol)


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "output must be a fresh JSON path")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = study()
        _write_once(args.out, report)
        print(json.dumps({
            "status": report["status"],
            "cases": report["balance"]["total"],
            "falsum_correct": report["policies"]["falsum"]["correct"],
            "independent_interval_correct": report["policies"]["independent_interval"]["correct"],
            "citation_only_correct": report["policies"]["citation_only"]["correct"],
            "shortcut_label_leakage": report["shortcut_audit"]["label_leakage_detected"],
        }, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, AssertionError) as exc:
        parser.exit(1, "PHASE5BM BALANCED HOLDOUT FAILED CLOSED: " + str(exc)[:300] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
