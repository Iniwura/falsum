"""Portable, original-Git-blob-verified advisory source cache for Phase 5Z.

A cache is not a network response, freshness attestation, expert review, or a
new security finding. It only permits offline rechecking of the six historical
npm/lodash@4.17.15 GHSA source documents selected in Phase 5Y.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
from pathlib import Path

from .phase4l_external_receipt_evidence import git_blob_sha
from .phase5m_real_source_sensitive_model import ROOT
from .phase5y_original_reviewed_version_applicability import (
    ADVISORY_COMMIT, ADVISORY_REPO, REVIEWED_PREFIX, TARGET,
    _fetch_reviewed, frozen, load_reviewed,
)

STATUS = "FALSUM_ORIGINAL_PINNED_REVIEWED_ADVISORY_OFFLINE_BUNDLE_V1"
MAX_BUNDLE_BYTES = 2_000_000


class BundleError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BundleError(reason)


def no_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key in source bundle")
        result[key] = value
    return result


def build_bundle(*, root: Path = ROOT, download=None) -> dict:
    """Fetch the six immutable upstream sources, not third-party Miner bodies."""
    if download is None:
        download = _fetch_reviewed
    policy = frozen(root)
    cached = {}

    def capture(url: str) -> bytes:
        require(url.startswith(REVIEWED_PREFIX), "unapproved advisory source URL")
        raw = download(url)
        require(type(raw) is bytes and 0 < len(raw) <= 200_000,
                "original advisory source must be bounded bytes")
        cached[url] = raw
        return raw

    # Validate all 6 original byte identities, exact npm package ranges and
    # expected results before allowing even one byte to be exported.
    sources, _ = load_reviewed(root=root, download=capture)
    require(len(sources) == 6 and len(cached) == 6, "incomplete source population")
    return {
        "schema_version": 1,
        "status": STATUS,
        "original_source_repository": ADVISORY_REPO,
        "original_source_commit": ADVISORY_COMMIT,
        "historical_target": TARGET,
        "original_reviewed_source_count": 6,
        "contains_external_miner_response_bodies": False,
        "current_advisory_freshness_verified": False,
        "approved_security_decision": False,
        "network_evaluator_registered": False,
        "original_reviewed_source_bytes_base64": {
            spec["id"]: base64.b64encode(cached[
                REVIEWED_PREFIX + spec["source_path"]
            ]).decode("ascii")
            for spec in policy["original_advisory_sources"]
        },
    }


def load_bundle(path: Path, *, root: Path = ROOT) -> list[dict]:
    """Use only an entire original authenticated six-source snapshot, offline."""
    policy = frozen(root)
    require(path.is_file() and not path.is_symlink()
            and 0 < path.stat().st_size <= MAX_BUNDLE_BYTES,
            "offline bundle must be a regular bounded file")
    try:
        obj = json.loads(path.read_bytes().decode("utf-8", "strict"),
                         object_pairs_hook=no_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleError("malformed source bundle JSON") from exc
    require(isinstance(obj, dict) and set(obj) == {
        "schema_version", "status", "original_source_repository",
        "original_source_commit", "historical_target",
        "original_reviewed_source_count", "contains_external_miner_response_bodies",
        "current_advisory_freshness_verified", "approved_security_decision",
        "network_evaluator_registered", "original_reviewed_source_bytes_base64",
    }, "missing or unrecognized source bundle manifest fields")
    require(obj["schema_version"] == 1 and obj["status"] == STATUS
            and obj["original_source_repository"] == ADVISORY_REPO
            and obj["original_source_commit"] == ADVISORY_COMMIT
            and obj["historical_target"] == TARGET
            and type(obj["original_reviewed_source_count"]) is int
            and obj["original_reviewed_source_count"] == 6
            and obj["contains_external_miner_response_bodies"] is False
            and obj["current_advisory_freshness_verified"] is False
            and obj["approved_security_decision"] is False
            and obj["network_evaluator_registered"] is False,
            "offline bundle source identity, scope or claims changed")
    entries = obj["original_reviewed_source_bytes_base64"]
    specs = policy["original_advisory_sources"]
    require(isinstance(entries, dict)
            and set(entries) == {s["id"] for s in specs},
            "offline advisory source roster incomplete or expanded")
    raw_by_url = {}
    for spec in specs:
        encoded = entries[spec["id"]]
        require(type(encoded) is str and 0 < len(encoded) <= 270_000,
                "missing or oversized encoded original reviewed source")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BundleError("invalid upstream source base64") from exc
        require(base64.b64encode(raw).decode("ascii") == encoded
                and 0 < len(raw) <= 200_000
                and git_blob_sha(raw) == spec["original_git_blob_sha1"],
                "noncanonical, missing or tampered original Git advisory source bytes")
        raw_by_url[REVIEWED_PREFIX + spec["source_path"]] = raw

    def offline_only(url: str) -> bytes:
        require(url in raw_by_url, "unknown original advisory URL")
        return raw_by_url[url]

    rows, _ = load_reviewed(root=root, download=offline_only)
    require(len(rows) == 6, "offline source verification incomplete")
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export six authenticated historical GitHub-reviewed advisory bytes for offline use"
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(args.out.suffix == ".json" and not args.out.is_symlink()
                and not args.out.exists(), "bundle output must be fresh write-once JSON")
        bundle = build_bundle()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as f:
            json.dump(bundle, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
        # Verify the exact exported bytes through the offline loader.
        load_bundle(args.out)
        print(json.dumps({
            "status": STATUS, "original_git_sources_verified": 6,
            "offline_usable": True, "new_network_requests_to_telegraph": 0,
            "independent_expert_gold": 0, "external_adoption_claim": False,
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, "FAIL-CLOSED REVIEWED SOURCE BUNDLE: " + str(exc)[:280] + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
