"""Phase 3Z: real source-catalogue package-version reversals, NOT expert labels.

Each package's affected/patched version is checked against an immutable GitHub
Advisory Database JSON Git blob, and both releases against live PyPI metadata.
No model is scored here. The public cases are NOT a sealed blind model holdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

STATUS = "PHASE3Z_REAL_PUBLIC_ADVISORY_VERSION_PAIRS_RESEARCH_ONLY"
PINNED_DB_COMMIT = "b2a0c7d47ab94089f8774eacdc65ad80f2457170"
INTENT = "SECURITY_REVIEW_GENERAL"
# (advisory id, immutable reviewed path, git blob SHA-1, PyPI package,
#  introduced, fixed, selected affected version, selected fixed version,
#  count of complete affected-records in that advisory)
PINS = (
    ("GHSA-vqxf-v2gg-x3hc",
     "advisories/github-reviewed/2026/01/GHSA-vqxf-v2gg-x3hc/GHSA-vqxf-v2gg-x3hc.json",
     "08524c7fd01eed1ad3751cf8c9bd90edf55e2139",
     "docling-core", "2.21.0", "2.48.4", "2.48.3", "2.48.4", 1),
    ("GHSA-wf6j-7hvr-gr93",
     "advisories/github-reviewed/2026/10/GHSA-wf6j-7hvr-gr93/GHSA-wf6j-7hvr-gr93.json",
     "c6a94015fb6b665c74a339e3660600098452d441",
     "hydra-core", "1.3.6", "1.3.8", "1.3.7", "1.3.8", 2),
    ("GHSA-mj87-hwqh-73pj",
     "advisories/github-reviewed/2026/04/GHSA-mj87-hwqh-73pj/GHSA-mj87-hwqh-73pj.json",
     "e0ec8c75dbc31b40e438c0872449c9e33e0ba4e1",
     "python-multipart", "0", "0.0.26", "0.0.25", "0.0.26", 1),
)
PRIOR_STUDIED = frozenset({
    "aiohttp", "requests", "jinja", "axios", "starlette", "urllib3",
    "django", "express", "tornado", "undici", "websockets",
})
ANSWER_A = ("For this exact pinned advisory record, the declared version is "
            "within the affected version interval. That warrants dependency review, "
            "not a claim that an application reaches the vulnerable code.")
ANSWER_B = ("For this exact pinned advisory record, the declared version is "
            "outside the affected version interval. That does not establish that "
            "other advisories or application security problems are absent.")
SHA40 = re.compile(r"^[a-f0-9]{40}$")
DATE_CUTOFF = "2026-11-12T23:59:59+00:00"


class Phase3ZError(ValueError):
    """Fail closed on malformed provenance, irrelevant cases or invented claims."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Phase3ZError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def numeric_version(version: str) -> tuple[int, ...]:
    """Only parse the exact stable numeric version branch used by these three pins.

    This is NOT a general PEP 440 / SemVer dependency range parser; prerelease
    ranges are explicitly excluded instead of being interpreted incorrectly.
    """
    require(isinstance(version, str) and re.fullmatch(r"(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){0,3}", version)
            is not None, "unsupported prerelease or nonnumeric version: " + repr(version))
    return tuple(int(x) for x in version.split("."))


def cmp_version(left: str, right: str) -> int:
    a, b = numeric_version(left), numeric_version(right)
    n = max(len(a), len(b))
    a += (0,) * (n - len(a))
    b += (0,) * (n - len(b))
    return (a > b) - (a < b)


def advisory_url(pin: tuple) -> str:
    return ("https://raw.githubusercontent.com/github/advisory-database/"
            + PINNED_DB_COMMIT + "/" + pin[1])


def pypi_url(package: str, version: str) -> str:
    require(re.fullmatch(r"[a-z0-9-]+", package) is not None,
            "unexpected PyPI package")
    numeric_version(version)
    return f"https://pypi.org/pypi/{package}/{version}/json"


def bounded_download(url: str) -> bytes:
    """Only fixed, public, HTTPS sources. Reject redirect and oversized responses."""
    require(url.startswith(
        "https://raw.githubusercontent.com/github/advisory-database/"
        + PINNED_DB_COMMIT + "/advisories/github-reviewed/"
    ) or any(url == pypi_url(p[3], v) for p in PINS for v in (p[6], p[7])),
        "unexpected external URL")
    request = Request(url, headers={
        "User-Agent": "FALSUM-phase3z-pinned-source-audit/1",
        "Accept": "application/json",
    })
    try:
        with urlopen(request, timeout=25) as response:
            require(response.geturl() == url and response.status == 200,
                    "unexpected response URL or HTTP status")
            data = response.read(1_000_001)
    except (OSError, ValueError) as e:
        raise Phase3ZError("cannot verify actual official source: " + url) from e
    require(0 < len(data) <= 1_000_000, "unbounded or missing upstream JSON")
    return data


def validate_pin(pin: tuple) -> None:
    require(len(pin) == 9, "pin schema has changed")
    ghsa, path, blob, package, introduced, fixed, before, after, row_count = pin
    require(re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa) is not None,
            "invalid GHSA id")
    require(path.startswith("advisories/github-reviewed/") and path.endswith("/" + ghsa + ".json")
            and ".." not in path and SHA40.fullmatch(blob) is not None,
            "unapproved upstream advisory identity")
    require(package not in PRIOR_STUDIED and re.fullmatch(r"[a-z0-9-]+", package),
            "overlapping project or malformed package")
    for version in (introduced, fixed, before, after):
        numeric_version(version)
    require(cmp_version(introduced, before) <= 0 and cmp_version(before, fixed) < 0
            and after == fixed and cmp_version(fixed, introduced) > 0,
            "incorrect version boundary or no reversal")
    require(type(row_count) is int and row_count in (1, 2), "untrusted range coverage")


def check_advisory(pin: tuple, data: bytes) -> tuple[str, dict]:
    validate_pin(pin)
    ghsa, _, blob, package, introduced, fixed, _, _, row_count = pin
    require(git_blob_sha1(data) == blob, "Git blob identity disagrees with pinned reviewed GHSA")
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeError) as e:
        raise Phase3ZError("invalid advisory JSON") from e
    require(isinstance(payload, dict) and payload.get("id") == ghsa
            and isinstance(payload.get("published"), str)
            and payload.get("published") <= "2026-11-13"
            and not payload.get("withdrawn"), "wrong, future or withdrawn advisory")
    affected = payload.get("affected")
    require(isinstance(affected, list) and len(affected) == row_count,
            "advisory contains new or missing ranges; re-review all ranges")
    match = [
        row for row in affected
        if isinstance(row, dict) and row.get("package") == {
            "ecosystem": "PyPI", "name": package
        } and row.get("ranges") == [{
            "type": "ECOSYSTEM",
            "events": [{"introduced": introduced}, {"fixed": fixed}]
        }]
    ]
    require(len(match) == 1, "expected exact stable-branch affected range missing")
    require(all(isinstance(row, dict)
                and row.get("package") == {"ecosystem": "PyPI", "name": package}
                for row in affected), "unexpected package or ecosystem on pinned record")
    return sha256(data), payload


def check_release(package: str, version: str, data: bytes) -> dict:
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeError) as e:
        raise Phase3ZError("invalid PyPI release metadata") from e
    require(isinstance(payload, dict) and isinstance(payload.get("info"), dict)
            and payload["info"].get("name", "").lower().replace("_", "-") == package
            and payload["info"].get("version") == version,
            "PyPI returned a different package or release")
    urls = payload.get("urls")
    require(isinstance(urls, list) and 0 < len(urls) <= 20
            and all(isinstance(item, dict) and item.get("yanked") is False
                    and item.get("digests", {}).get("sha256")
                    and item.get("upload_time_iso_8601") for item in urls),
            "missing, yanked, or unverified release artifacts")
    earliest = min(u["upload_time_iso_8601"] for u in urls)
    require(earliest[:10] <= "2026-11-12", "release published after frozen source cutoff")
    return {
        "release": version, "release_url": pypi_url(package, version),
        "actual_pypi_release_metadata_sha256": sha256(data),
        "actual_pypi_file_count": len(urls),
        "first_upload_utc": earliest,
        "not_yanked_at_verification": True,
    }


def assemble(fetcher=bounded_download) -> dict:
    """True live-source verification. Unit tests use explicitly synthetic fetchers."""
    require(len(PINS) == 3 and len({p[3] for p in PINS}) == 3
            and len({p[0] for p in PINS}) == 3,
            "expected three truly different package projects")
    cases = []
    provenances = []
    for pin in PINS:
        validate_pin(pin)
        ghsa, _, blob, package, introduced, fixed, before, after, row_count = pin
        raw = fetcher(advisory_url(pin))
        digest, _ = check_advisory(pin, raw)
        releases = [check_release(package, v, fetcher(pypi_url(package, v)))
                    for v in (before, after)]
        provenances.append({
            "ghsa": ghsa, "package": package, "pinned_advisory_git_blob_sha1": blob,
            "pinned_advisory_json_sha256": digest,
            "pinned_advisory_raw_url": advisory_url(pin),
            "verified_pypi_releases": releases,
            "complete_advisory_affected_ranges": row_count,
            "stable_numeric_range_evaluated_only": True,
        })
        for version, expected in ((before, "A"), (after, "B")):
            cases.append({
                "case_id": package + "-" + version,
                "question": (
                    "A pull request declares the direct PyPI dependency "
                    + package + "==" + version + ". Evaluate only its status "
                    "under the single pinned GitHub Reviewed " + ghsa
                    + " advisory's numeric affected-version range. "
                    "Do not infer application exploitability, transitive "
                    "dependencies or absence of other advisories. Which finding "
                    "is supported by the published advisory record?"
                ),
                "candidate_answers": [
                    {"id": "A", "text": ANSWER_A},
                    {"id": "B", "text": ANSWER_B},
                ],
                "mechanically_source_derived_preference": expected,
                "version_in_this_one_advisory_range": expected == "A",
                "advisory": ghsa,
                "source_package": package,
                "source_release": version,
                "public_catalogue_question_not_independent_expert_label": True,
                "model_score_measured": False,
                "training_authorized": False,
            })
    require(len(cases) == 6 and len({x["case_id"] for x in cases}) == 6
            and [x["mechanically_source_derived_preference"] for x in cases]
            == ["A", "B"] * 3, "constant-answer shortcut or duplicated case")
    return {
        "schema_version": 1, "status": STATUS, "intent": INTENT,
        "snapshot_cutoff_utc": DATE_CUTOFF,
        "pinned_public_advisory_database_commit": PINNED_DB_COMMIT,
        "catalogue_source_verified_by_exact_git_blobs": True,
        "live_pypi_release_existence_checked": True,
        "distinct_package_projects": 3, "case_count": 6,
        "catalogue_version_reversal_pairs": 3,
        "source_catalogue_expected_A": 3, "source_catalogue_expected_B": 3,
        "provenance": provenances, "cases": cases,
        "not_model_pretraining_disjoint": True,
        "not_blind_or_private_holdout": True,
        "not_independent_expert_reviewed": True,
        "independent_expert_labels": 0,
        "new_network_eligible_rows": 0,
        "model_scores_measured": False,
        "registered_evaluator": False,
        "automatic_registration_permitted": False,
        "trainable_pairs": [],
        "notice": (
            "Six mechanically checked public GitHub Advisory Database version-status "
            "questions covering three new packages. These verify catalogue inclusion "
            "only, not exploits, downstream reachability, other advisories, a trained "
            "evaluator or independently adjudicated security accuracy."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Verify public Phase3Z advisory versions, no model training")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists() or args.out.is_symlink():
            raise Phase3ZError("refuse to overwrite prior official catalogue evidence")
        report = assemble()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps({
            "status": STATUS, "real_verified_source_packages": 3,
            "measured_version_cases": 6, "label_source": "public advisory catalogue",
            "actual_model_scores": False, "network_rows": 0, "human_approved_labels": 0,
        }, indent=2))
        return 0
    except (OSError, Phase3ZError, TypeError, KeyError, IndexError) as error:
        parser.exit(1, "FALSUM PHASE3Z SOURCE CHECK FAILED: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
