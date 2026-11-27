"""Phase 5BJ: frozen public-provider holdout and version-aware comparison.

This study consumes two response captures selected from a public provider Git
tree *before* their bodies were inspected.  It authenticates the provider
blobs and the pinned GitHub Advisory Database blobs, binds every decision to
the request envelope's ecosystem/package/version, and compares the FALSUM
interval policy with a separately implemented competent interval baseline.

The provider response is intentionally reduced in memory to target identity,
reference identifiers and structural payment flags.  Receipt, payment header,
and raw response content are never returned in the report or committed as
evidence.  This is a public holdout measurement, not AppSec gold, recall,
security clearance, customer adoption, or a paid Telegraph execution.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.request import Request, urlopen

from .phase4l_external_receipt_evidence import git_blob_sha
from .phase5m_real_source_sensitive_model import ROOT


STATUS = "PHASE5BJ_FRESH_PUBLIC_PROVIDER_HOLDOUT_VERSION_AWARE_COMPARISON"
PROTOCOL = "data/phase5bj-fresh-provider-holdout-protocol.json"
PROTOCOL_BLOB = "0b51a6b645f38aaeb31ace53e6bbde146a2d3bf6"
PROVIDER_REPOSITORY = "anvithagowda098/pr-guard"
PROVIDER_COMMIT = "99d2e3c93890a8fc083947bde4f21217516b7a5f"
ADVISORY_REPOSITORY = "github/advisory-database"
ADVISORY_COMMIT = "76955defc62d048f8f7cc68bc39a2f6dd1899ebe"
PROVIDER_BASE = f"https://raw.githubusercontent.com/{PROVIDER_REPOSITORY}/{PROVIDER_COMMIT}/"
ADVISORY_BASE = f"https://raw.githubusercontent.com/{ADVISORY_REPOSITORY}/{ADVISORY_COMMIT}/"
MAX_BLOB = 2_500_000
NUMERIC = re.compile(r"^(?:0|[0-9]+(?:\.[0-9]+){0,3})$")
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")

SELECTED = {
    "test/fixtures/miner-responses/SECURITY_REVIEW/190048-pypi-django-3.2.0-200-paid.json":
        "58959d9239b621cf7adec4ae4bcdf3d01ca2b9f1",
    "test/fixtures/miner-responses/SECURITY_REVIEW/77010-npm-lodash-4.18.1-200-paid.json":
        "96ab6123b2746ef54e1017dd64f62f9bcaa94b6e",
}

# The path and Git blob identity were resolved from the pinned advisory tree
# after the provider holdout was frozen.  Only metadata and hashes are kept.
SOURCE_SPECS: dict[str, tuple[str, str]] = {
    "GHSA-68w8-qjq3-2gfm": ("advisories/github-reviewed/2021/06/GHSA-68w8-qjq3-2gfm/GHSA-68w8-qjq3-2gfm.json", "ac15ab00991f9cf21d264e8f08a4409da6630749"),
    "GHSA-p99v-5w3c-jqq9": ("advisories/github-reviewed/2021/06/GHSA-p99v-5w3c-jqq9/GHSA-p99v-5w3c-jqq9.json", "04aa72396ad707dafa6c2cea8fa5d5ee74e60fa2"),
    "GHSA-qm57-vhq3-3fwf": ("advisories/github-reviewed/2021/06/GHSA-qm57-vhq3-3fwf/GHSA-qm57-vhq3-3fwf.json", "473106f8639c755be1f7f12d62b6a19b81246eff"),
    "GHSA-rxjp-mfm9-w4wr": ("advisories/github-reviewed/2021/06/GHSA-rxjp-mfm9-w4wr/GHSA-rxjp-mfm9-w4wr.json", "ec59353efd6e064f51225594bc22bead1f366d67"),
    "GHSA-xpfp-f569-q3p2": ("advisories/github-reviewed/2021/09/GHSA-xpfp-f569-q3p2/GHSA-xpfp-f569-q3p2.json", "c87cc5ae14a72ec71d00aeccb77b56931cedb4c5"),
    "GHSA-v6rh-hp5x-86rv": ("advisories/github-reviewed/2021/12/GHSA-v6rh-hp5x-86rv/GHSA-v6rh-hp5x-86rv.json", "92491ca6eb98b6cb09bdac1caf0635fa7cca7573"),
    "GHSA-53qw-q765-4fww": ("advisories/github-reviewed/2022/01/GHSA-53qw-q765-4fww/GHSA-53qw-q765-4fww.json", "b5735326f8fd48f3ccd43389998c87553d60334f"),
    "GHSA-8c5j-9r9f-c6w8": ("advisories/github-reviewed/2022/01/GHSA-8c5j-9r9f-c6w8/GHSA-8c5j-9r9f-c6w8.json", "4af8a84edb090a94b16bfae68dd56ea98e9f916a"),
    "GHSA-jrh2-hc4r-7jwx": ("advisories/github-reviewed/2022/01/GHSA-jrh2-hc4r-7jwx/GHSA-jrh2-hc4r-7jwx.json", "379b580ad8302314d5efbf83d8b597da497e4045"),
    "GHSA-6cw3-g6wv-c2xv": ("advisories/github-reviewed/2022/02/GHSA-6cw3-g6wv-c2xv/GHSA-6cw3-g6wv-c2xv.json", "e398c781b2d573c69a2e088cb89fa3eaf7e7e75a"),
    "GHSA-95rw-fx8r-36v6": ("advisories/github-reviewed/2022/02/GHSA-95rw-fx8r-36v6/GHSA-95rw-fx8r-36v6.json", "0e34a138f559c929e8ad71f1836e7282e683379d"),
    "GHSA-2gwj-7jmv-h26r": ("advisories/github-reviewed/2022/04/GHSA-2gwj-7jmv-h26r/GHSA-2gwj-7jmv-h26r.json", "45661d47b8b72e19b70243f5c4839d5957895180"),
    "GHSA-w24h-v9qh-8gxj": ("advisories/github-reviewed/2022/04/GHSA-w24h-v9qh-8gxj/GHSA-w24h-v9qh-8gxj.json", "f44ccb6675a19cf3d66ac92447442af5a4079d36"),
    "GHSA-p64x-8rxx-wf6q": ("advisories/github-reviewed/2022/07/GHSA-p64x-8rxx-wf6q/GHSA-p64x-8rxx-wf6q.json", "79bdf3852935d283544ebc42cf65f2c8595e5112"),
    "GHSA-8x94-hmjh-97hq": ("advisories/github-reviewed/2022/08/GHSA-8x94-hmjh-97hq/GHSA-8x94-hmjh-97hq.json", "e23da87f89bb88547f3f9279fa3ff6955c6b8fa5"),
    "GHSA-qrw5-5h28-6cmg": ("advisories/github-reviewed/2022/10/GHSA-qrw5-5h28-6cmg/GHSA-qrw5-5h28-6cmg.json", "f70a2ba5f84c3cbd6b585f9b8969189c4c7eaa46"),
    "GHSA-2hrw-hx67-34x6": ("advisories/github-reviewed/2023/02/GHSA-2hrw-hx67-34x6/GHSA-2hrw-hx67-34x6.json", "9612d1f713af0eefae127155baac02553f03cef6"),
    "GHSA-q2jf-h9jm-m7p4": ("advisories/github-reviewed/2023/02/GHSA-q2jf-h9jm-m7p4/GHSA-q2jf-h9jm-m7p4.json", "995a9c1948b98d2c70ad89b88a5c588e53520b2c"),
    "GHSA-r3xc-prgr-mg9p": ("advisories/github-reviewed/2023/05/GHSA-r3xc-prgr-mg9p/GHSA-r3xc-prgr-mg9p.json", "c13d9150a14e68d57f34917f27a0676b29f87680"),
    "GHSA-jh3w-4vvf-mjgr": ("advisories/github-reviewed/2023/07/GHSA-jh3w-4vvf-mjgr/GHSA-jh3w-4vvf-mjgr.json", "c891f5443a7f717636e9fc3294e45be9b4c65420"),
    "GHSA-7h4p-27mh-hmrw": ("advisories/github-reviewed/2023/11/GHSA-7h4p-27mh-hmrw/GHSA-7h4p-27mh-hmrw.json", "ba19ef1dbbbb620f01520904a1ffe7a784098cf1"),
    "GHSA-h8gc-pgj2-vjm3": ("advisories/github-reviewed/2023/11/GHSA-h8gc-pgj2-vjm3/GHSA-h8gc-pgj2-vjm3.json", "562e1289bfbe10b0aeb27e61ea92bc7389aed97c"),
    "GHSA-qmf9-6jqf-j8fq": ("advisories/github-reviewed/2023/11/GHSA-qmf9-6jqf-j8fq/GHSA-qmf9-6jqf-j8fq.json", "422f6e781ef8886262d1e4f8c2a26ca8bcd150ca"),
    "GHSA-xxj9-f6rv-m3x4": ("advisories/github-reviewed/2024/02/GHSA-xxj9-f6rv-m3x4/GHSA-xxj9-f6rv-m3x4.json", "d40e098f33decd8f1103da9e5c8fd8dbd104b134"),
    "GHSA-vm8q-m57g-pff3": ("advisories/github-reviewed/2024/03/GHSA-vm8q-m57g-pff3/GHSA-vm8q-m57g-pff3.json", "612a412374c90d3945ead4a1d693e92b204de041"),
    "GHSA-rrqc-c2jx-6jgv": ("advisories/github-reviewed/2024/10/GHSA-rrqc-c2jx-6jgv/GHSA-rrqc-c2jx-6jgv.json", "114ec369059573e902a04b7765002d1f676e8712"),
    "GHSA-7xr5-9hcq-chf9": ("advisories/github-reviewed/2025/06/GHSA-7xr5-9hcq-chf9/GHSA-7xr5-9hcq-chf9.json", "ace1e167d4a438cdb462671efaf6304f1096d771"),
    "GHSA-6w2r-r2m5-xq5w": ("advisories/github-reviewed/2025/09/GHSA-6w2r-r2m5-xq5w/GHSA-6w2r-r2m5-xq5w.json", "bbd655506e78540fcb6c690621981c2c2cd74342"),
    "GHSA-frmv-pr5f-9mcr": ("advisories/github-reviewed/2025/11/GHSA-frmv-pr5f-9mcr/GHSA-frmv-pr5f-9mcr.json", "75ff6c28c0f4b5be387213bfebfe57c2f30ce676"),
    "GHSA-qw25-v68c-qjf3": ("advisories/github-reviewed/2025/11/GHSA-qw25-v68c-qjf3/GHSA-qw25-v68c-qjf3.json", "d0b889ad643de1ed12f32dcb26e58b97fc88d016"),
    "GHSA-8cjm-8mp7-r2xf": ("advisories/github-reviewed/2026/06/GHSA-8cjm-8mp7-r2xf/GHSA-8cjm-8mp7-r2xf.json", "39a931c70fffdffd8d2416f22f5568d8e8b49b87"),
    "GHSA-923m-gv2p-w5qp": ("advisories/github-reviewed/2026/06/GHSA-923m-gv2p-w5qp/GHSA-923m-gv2p-w5qp.json", "795b581967cfc621a6697800534940bdfb12fb1a"),
    "GHSA-h7pc-vwp9-298g": ("advisories/github-reviewed/2026/06/GHSA-h7pc-vwp9-298g/GHSA-h7pc-vwp9-298g.json", "f6045e098948be553ab22f8104c3bd973284b142"),
    "GHSA-3h9f-r86x-qvjx": ("advisories/github-reviewed/2026/07/GHSA-3h9f-r86x-qvjx/GHSA-3h9f-r86x-qvjx.json", "b7c6f533f26e6f3869f1b31f008ba3f97a491d5c"),
    "GHSA-8qcx-xf44-272x": ("advisories/github-reviewed/2026/07/GHSA-8qcx-xf44-272x/GHSA-8qcx-xf44-272x.json", "50130cb55e76028171ee2f375b0db04a5053599e"),
    "GHSA-crhf-3pfg-w68w": ("advisories/github-reviewed/2026/07/GHSA-crhf-3pfg-w68w/GHSA-crhf-3pfg-w68w.json", "b3d43fb9f51466c57315b327b7951950379f7780"),
    "GHSA-q238-5cxm-5c9h": ("advisories/github-reviewed/2026/08/GHSA-q238-5cxm-5c9h/GHSA-q238-5cxm-5c9h.json", "642dd9cb74d6c450c547d68f57e70755b419ffd5"),
    "GHSA-wvqv-fj8w-qmhm": ("advisories/github-reviewed/2026/08/GHSA-wvqv-fj8w-qmhm/GHSA-wvqv-fj8w-qmhm.json", "b71fbea24554f6b4b4fe0ac3f1111de7e40ff655"),
}

APPLICABLE = "APPLICABLE"
INAPPLICABLE = "INAPPLICABLE"
UNKNOWN = "UNKNOWN_OR_INSUFFICIENT"
DUPLICATE = "DUPLICATE_NOT_DOUBLE_COUNTED"


class HoldoutError(ValueError):
    """Raised when the frozen public holdout cannot be authenticated."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise HoldoutError(message)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        need(key not in result, "duplicate JSON object key in frozen public evidence")
        result[key] = value
    return result


def strict_json(raw: bytes) -> object:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HoldoutError("malformed public JSON evidence") from exc


def fetch_bytes(url: str, *, base: str, max_bytes: int = MAX_BLOB) -> bytes:
    need(url.startswith(base), "unexpected public source URL")
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "FALSUM-phase5bj-holdout/1.0"})
    with urlopen(request, timeout=30) as response:
        need(response.status == 200 and response.geturl() == url, "public source unavailable or redirected")
        raw = response.read(max_bytes + 1)
    need(0 < len(raw) <= max_bytes, "public source exceeds fixed byte cap")
    return raw


def frozen_protocol(root: Path = ROOT) -> dict[str, Any]:
    raw = (root / PROTOCOL).read_bytes()
    need(git_blob_sha(raw) == PROTOCOL_BLOB, "fresh-provider protocol changed after freeze")
    protocol = strict_json(raw)
    need(isinstance(protocol, dict)
         and protocol.get("schema_version") == 1
         and protocol.get("status") == "PHASE5BJ_FRESH_PUBLIC_PROVIDER_HOLDOUT_FROZEN_BEFORE_OBSERVATION"
         and protocol.get("provider_source_repository") == PROVIDER_REPOSITORY
         and protocol.get("provider_source_git_commit") == PROVIDER_COMMIT,
         "invalid fresh-provider protocol identity")
    expected = [
        {"path": path, "provider_role": "direct_versioned_security_review"}
        for path in SELECTED
    ]
    rows = protocol.get("selected_fresh_capture_paths")
    need(isinstance(rows, list) and len(rows) == 2
         and all(isinstance(row, dict) and row.get("path") == item["path"]
                 and row.get("provider_role") == item["provider_role"]
                 for row, item in zip(rows, expected)),
         "selected fresh capture paths changed")
    source = protocol.get("independent_reference_source")
    need(isinstance(source, dict)
         and source.get("repository") == ADVISORY_REPOSITORY
         and source.get("git_commit") == ADVISORY_COMMIT,
         "independent advisory source changed")
    contract = protocol.get("evaluation_contract")
    need(isinstance(contract, dict)
         and "competent_baseline" in contract
         and "explicit abstention on unsupported ranges" in contract["competent_baseline"],
         "competent baseline contract was weakened")
    limits = protocol.get("explicit_limits")
    need(isinstance(limits, dict) and len(limits) >= 10 and all(value is True for value in limits.values()),
         "fresh-provider limits were weakened")
    return protocol


def _provider_capture(path: str, raw: bytes) -> dict[str, Any]:
    need(git_blob_sha(raw) == SELECTED[path], f"provider blob changed: {path}")
    capture = strict_json(raw)
    need(isinstance(capture, dict)
         and isinstance(capture.get("request"), dict)
         and capture["request"].get("method") == "GET"
         and capture["request"].get("endpoint") == "/query",
         "provider request envelope is not the frozen query shape")
    payload = capture["request"].get("payload")
    need(isinstance(payload, dict) and isinstance(payload.get("pkg"), str)
         and isinstance(payload.get("ver"), str), "provider target envelope is incomplete")
    result = capture.get("body", {}).get("result") if isinstance(capture.get("body"), dict) else None
    need(isinstance(result, dict), "provider result is not an object")
    package = payload["pkg"]
    version = payload["ver"]
    requested_system = payload.get("system")
    if requested_system == "pypi":
        target = {"ecosystem": "PyPI", "package": package, "version": version}
        version_key = result.get("versionKey")
        need(isinstance(version_key, dict)
             and version_key.get("name") == package
             and version_key.get("system") == "PYPI"
             and version_key.get("version") == version,
             "provider result target does not bind to the PyPI request")
        advisory_values = result.get("advisoryKeys")
    else:
        target = {"ecosystem": "npm", "package": package, "version": version}
        version_row = result.get("version")
        package_row = result.get("package")
        need(isinstance(version_row, dict) and isinstance(package_row, dict)
             and version_row.get("version") == version
             and package_row.get("name") == package
             and str(package_row.get("system", "")).lower() == "npm",
             "provider result target does not bind to the npm request")
        advisory_values = version_row.get("advisories")
    if advisory_values is None:
        advisory_values = result.get("advisoryKeys")
    need(isinstance(advisory_values, list), "provider advisory list is not present")
    references: list[str] = []
    for row in advisory_values:
        identifier = row.get("id") if isinstance(row, dict) else row
        need(isinstance(identifier, str) and 0 < len(identifier) <= 128,
             "provider advisory identifier is malformed")
        references.append(identifier)
    need(len(references) == len(set(references)), "provider advisory list contains duplicate identifiers")
    need(capture.get("status") == 200 and capture.get("paid") is True and capture.get("charged") is True,
         "provider capture is not the frozen paid/HTTP-200 structural shape")
    miner_id = capture.get("body", {}).get("miner_id") if isinstance(capture.get("body"), dict) else None
    need(isinstance(miner_id, str) and miner_id, "provider miner identity missing")
    # Deliberately return no response body, receipt, payment object or token.
    return {
        "path": path,
        "provider_blob_sha1": SELECTED[path],
        "miner_id": miner_id,
        "target": target,
        "reported_reference_ids": references,
        "structural_paid_http200": True,
    }


def _package_key(ecosystem: object, package: object) -> tuple[str, str] | None:
    if not isinstance(ecosystem, str) or not isinstance(package, str) or not package.strip():
        return None
    eco = ecosystem.strip().lower()
    # PyPI normalizes runs of '-', '_' and '.' and is case-insensitive. npm
    # package names are treated as exact strings for this bounded study.
    name = re.sub(r"[-_.]+", "-", package).lower() if eco == "pypi" else package
    return eco, name


def _numbers(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or len(value) > 48 or not NUMERIC.fullmatch(value):
        return None
    parts = tuple(int(part) for part in value.split("."))
    return parts if all(part <= 999999 for part in parts) else None


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    a = left + (0,) * (width - len(left))
    b = right + (0,) * (width - len(right))
    return (a > b) - (a < b)


def _falsum_interval(events: object, version: tuple[int, ...]) -> str:
    if not isinstance(events, list) or not events:
        return UNKNOWN
    opened: tuple[int, ...] | None = None
    saw_interval = False
    applicable = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return UNKNOWN
        key, raw_value = next(iter(event.items()))
        value = _numbers(raw_value)
        if value is None:
            return UNKNOWN
        if key == "introduced":
            if opened is not None:
                return UNKNOWN
            opened = value
        elif key in ("fixed", "last_affected"):
            if opened is None or _compare(value, opened) < 0:
                return UNKNOWN
            left = _compare(version, opened) >= 0
            right = _compare(version, value) < 0 if key == "fixed" else _compare(version, value) <= 0
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


def falsum_status(advisory: dict[str, Any], target: Mapping[str, object]) -> str:
    """The production-style fail-closed decision for one authenticated source."""
    if advisory.get("withdrawn"):
        return UNKNOWN
    target_key = _package_key(target.get("ecosystem"), target.get("package"))
    version = _numbers(target.get("version"))
    if target_key is None or version is None:
        return UNKNOWN
    selected = []
    for row in advisory.get("affected", []):
        package = row.get("package") if isinstance(row, dict) else None
        if not isinstance(package, dict):
            return UNKNOWN
        if _package_key(package.get("ecosystem"), package.get("name")) == target_key:
            selected.append(row)
    if not selected:
        return INAPPLICABLE
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
            result = _falsum_interval(item.get("events"), version)
            if result == APPLICABLE:
                return APPLICABLE
            if result == UNKNOWN:
                uncertain = True
    return UNKNOWN if uncertain or not observed else INAPPLICABLE


def _baseline_interval(events: object, version: tuple[int, ...]) -> str:
    """Independent baseline parser; intentionally does not call FALSUM helpers."""
    if not isinstance(events, list) or not events:
        return UNKNOWN
    intervals: list[tuple[tuple[int, ...], tuple[int, ...] | None, bool]] = []
    start: tuple[int, ...] | None = None
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return UNKNOWN
        key, raw = next(iter(event.items()))
        parsed = _numbers(raw)
        if parsed is None:
            return UNKNOWN
        if key == "introduced" and start is None:
            start = parsed
        elif key in ("fixed", "last_affected") and start is not None:
            if _compare(parsed, start) < 0:
                return UNKNOWN
            intervals.append((start, parsed, key == "last_affected"))
            start = None
        else:
            return UNKNOWN
    if start is not None:
        intervals.append((start, None, False))
    if not intervals:
        return UNKNOWN
    for left, right, inclusive in intervals:
        if _compare(version, left) < 0:
            continue
        if right is None or _compare(version, right) < 0 or (inclusive and _compare(version, right) == 0):
            return APPLICABLE
    return INAPPLICABLE


def baseline_status(advisory: dict[str, Any], target: Mapping[str, object]) -> str:
    """A separately implemented exact-target, numeric interval baseline."""
    if advisory.get("withdrawn"):
        return UNKNOWN
    target_key = _package_key(target.get("ecosystem"), target.get("package"))
    version = _numbers(target.get("version"))
    if target_key is None or version is None:
        return UNKNOWN
    rows = []
    for row in advisory.get("affected", []):
        pkg = row.get("package") if isinstance(row, dict) else None
        if not isinstance(pkg, dict):
            return UNKNOWN
        if _package_key(pkg.get("ecosystem"), pkg.get("name")) == target_key:
            rows.append(row)
    if not rows:
        return INAPPLICABLE
    saw_range = False
    had_unsupported = False
    for row in rows:
        ranges = row.get("ranges")
        if not isinstance(ranges, list):
            return UNKNOWN
        for item in ranges:
            if not isinstance(item, dict) or item.get("type") not in ("ECOSYSTEM", "SEMVER"):
                had_unsupported = True
                continue
            saw_range = True
            result = _baseline_interval(item.get("events"), version)
            if result == APPLICABLE:
                return APPLICABLE
            if result == UNKNOWN:
                had_unsupported = True
    return UNKNOWN if had_unsupported or not saw_range else INAPPLICABLE


def _load_sources(fetcher: Callable[..., bytes]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_identifier: dict[str, dict[str, Any]] = {}
    canonical: dict[str, dict[str, Any]] = {}
    for identifier, (path, expected_blob) in SOURCE_SPECS.items():
        need(GHSA.fullmatch(identifier) is not None and HEX40.fullmatch(expected_blob) is not None,
             "invalid pinned advisory source specification")
        raw = fetcher(ADVISORY_BASE + path, base=ADVISORY_BASE)
        need(git_blob_sha(raw) == expected_blob, f"advisory blob changed: {identifier}")
        advisory = strict_json(raw)
        need(isinstance(advisory, dict)
             and advisory.get("id") == identifier
             and isinstance(advisory.get("affected"), list)
             and isinstance(advisory.get("aliases"), list),
             f"advisory semantics missing: {identifier}")
        review = advisory.get("database_specific")
        need(isinstance(review, dict) and review.get("github_reviewed") is True,
             f"advisory is not authenticated as GitHub-reviewed: {identifier}")
        source = {
            "id": identifier,
            "path": path,
            "blob_sha1": expected_blob,
            "data": advisory,
        }
        canonical[identifier] = source
        for alias in [identifier, *advisory["aliases"]]:
            need(isinstance(alias, str) and alias and alias not in by_identifier,
                 "ambiguous advisory alias in pinned source set")
            by_identifier[alias] = source
    return by_identifier, canonical


def _evaluate_capture(capture: dict[str, Any], sources: Mapping[str, dict[str, Any]]) -> dict[str, Any]:
    target = capture["target"]
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for identifier in capture["reported_reference_ids"]:
        source = sources.get(identifier)
        row: dict[str, Any] = {"reported_identifier": identifier, "canonical_ghsa_id": None}
        if source is None:
            row.update({"falsum": UNKNOWN, "baseline": UNKNOWN, "reason": "IDENTIFIER_NOT_IN_PINNED_SOURCE_SET"})
        else:
            canonical = source["id"]
            row["canonical_ghsa_id"] = canonical
            row["source_path"] = source["path"]
            row["source_blob_sha1"] = source["blob_sha1"]
            if canonical in seen:
                row.update({"falsum": DUPLICATE, "baseline": DUPLICATE, "reason": "CANONICAL_ADVISORY_ALREADY_COUNTED"})
            else:
                seen.add(canonical)
                row["falsum"] = falsum_status(source["data"], target)
                row["baseline"] = baseline_status(source["data"], target)
                row["reason"] = "AUTHENTICATED_SOURCE_INTERVAL_EVALUATED"
        rows.append(row)
    comparable = [row for row in rows if row["falsum"] == row["baseline"]]
    counted = [row for row in rows if row["falsum"] != DUPLICATE]
    return {
        "path": capture["path"],
        "provider_blob_sha1": capture["provider_blob_sha1"],
        "miner_id": capture["miner_id"],
        "target": target,
        "structural_paid_http200": capture["structural_paid_http200"],
        "reported_reference_count": len(rows),
        "unique_reference_count": len(counted),
        "source_resolved_reference_count": sum(row["canonical_ghsa_id"] is not None for row in counted),
        "unknown_or_insufficient_count": sum(row["falsum"] == UNKNOWN for row in counted),
        "falsum_counts": {status: sum(row["falsum"] == status for row in counted) for status in (APPLICABLE, INAPPLICABLE, UNKNOWN)},
        "baseline_counts": {status: sum(row["baseline"] == status for row in counted) for status in (APPLICABLE, INAPPLICABLE, UNKNOWN)},
        "falsum_baseline_agreement_count": len(comparable),
        "falsum_baseline_disagreement_count": len(rows) - len(comparable),
        "decisions": rows,
    }


def study(root: Path = ROOT, *, fetcher: Callable[..., bytes] = fetch_bytes) -> dict[str, Any]:
    frozen_protocol(root)
    captures = []
    for path in SELECTED:
        raw = fetcher(PROVIDER_BASE + path, base=PROVIDER_BASE)
        captures.append(_provider_capture(path, raw))
    source_index, canonical_sources = _load_sources(fetcher)
    evaluated = [_evaluate_capture(capture, source_index) for capture in captures]
    report = {
        "schema_version": 1,
        "status": STATUS,
        "protocol": {"path": PROTOCOL, "git_blob_sha1": PROTOCOL_BLOB},
        "provider_source": {"repository": PROVIDER_REPOSITORY, "commit": PROVIDER_COMMIT},
        "independent_source": {"repository": ADVISORY_REPOSITORY, "commit": ADVISORY_COMMIT, "authenticated_canonical_sources": len(canonical_sources)},
        "captures": evaluated,
        "aggregate": {
            "reported_reference_count": sum(row["reported_reference_count"] for row in evaluated),
            "unique_reference_count": sum(row["unique_reference_count"] for row in evaluated),
            "source_resolved_reference_count": sum(row["source_resolved_reference_count"] for row in evaluated),
            "source_applicable_reference_count": sum(row["falsum_counts"][APPLICABLE] for row in evaluated),
            "source_inapplicable_reference_count": sum(row["falsum_counts"][INAPPLICABLE] for row in evaluated),
            "source_uncertain_or_unknown_count": sum(row["unknown_or_insufficient_count"] for row in evaluated),
            "falsum_baseline_disagreement_count": sum(row["falsum_baseline_disagreement_count"] for row in evaluated),
            "falsum_fail_closed_count": sum(row["falsum_counts"][UNKNOWN] for row in evaluated),
            "baseline_fail_closed_count": sum(row["baseline_counts"][UNKNOWN] for row in evaluated),
        },
        "interpretation": {
            "result": "The fresh provider evidence was evaluated without outcome-based reselection; FALSUM was compared with a separate exact-target numeric interval baseline.",
            "measurement_improvement_claimed": False,
            "independent_adoption_claimed": False,
            "security_clearance_granted": False,
            "new_paid_telegraph_execution": False,
        },
        "limits": [
            "This is not human AppSec gold, a blind model holdout, advisory recall, or current-feed completeness.",
            "A clean lodash response with zero reported advisories is a valid negative observation, not proof of security.",
            "Provider paid/charged flags are structural fields in a public capture, not independent settlement proof.",
            "No raw provider response, payment object, receipt, or token is included in this report.",
        ],
    }
    return report


def _write_once(path: Path, report: dict[str, Any]) -> None:
    need(path.suffix == ".json" and not path.exists() and not path.is_symlink(), "holdout output must be a fresh JSON path")
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
        print(json.dumps({"status": report["status"], "aggregate": report["aggregate"]}, sort_keys=True))
        return 0
    except (OSError, TypeError, ValueError, KeyError, AssertionError) as exc:
        parser.exit(1, "PHASE5BJ FRESH HOLDOUT FAILED CLOSED: " + str(exc)[:300] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
