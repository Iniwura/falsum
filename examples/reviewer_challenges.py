"""Offline, constructed-data falsification recipes for independent FALSUM reviewers.

Neither demonstration authenticates a new upstream source, claims a real Miner
response or alters any tracked file. Run with PYTHONPATH=src from repo root.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory

from falsum import phase5ab_original_receipt_comparability as audit
from falsum.phase4l_external_receipt_evidence import git_blob_sha
from falsum.phase5m_real_source_sensitive_model import ROOT


def constructed_capture() -> dict:
    return {
        "paid": True,
        "charged": True,
        "payment": {"success": True},
        "status": 200,
        "url": audit.ENGINE_ROUTED_URL,
        "request": {
            "intent": audit.CANONICAL,
            "params": {"target": "constructed test input, not a real paid request"},
        },
        "receipt": {
            "intent": audit.CANONICAL,
            "receipt_hash": "0x" + "a" * 64,
            "miner": "3854",
        },
        "body": {
            "miner_id": "77003",
            "signal_hash": "0x" + "b" * 64,
        },
    }


def direct_vs_routed() -> None:
    baseline = constructed_capture()
    direct = deepcopy(baseline)
    direct["url"] = audit.ENGINE_ROUTED_URL + "/77003"
    params = {"path": "ROUTED/constructed-review-challenge.json",
              "original_blob_sha1": "c" * 40}
    routed_result = audit.inspect(baseline, **params)
    direct_result = audit.inspect(direct, **params)
    assert routed_result["capture_intent_provenance_class"] == audit.KIND_ROUTED
    assert direct_result["capture_intent_provenance_class"] == audit.KIND_DIRECT
    assert direct_result["original_recorded_route_class"] == "DIRECT_MINER_ENDPOINT"
    assert direct_result["canonical_request_sha256"] is None
    assert routed_result["original_source_verified_by_git_blob"] is False
    assert direct_result["original_source_verified_by_git_blob"] is False
    print("PASS: CONSTRUCTED routed request becomes direct, not canonical, when only URL changes")
    print("PASS: Neither constructed capture inherits original Git source authentication")


def tampered_lock() -> None:
    authentic = (ROOT / audit.LOCK).read_bytes()
    assert git_blob_sha(authentic) == audit.LOCK_BLOB
    with TemporaryDirectory() as tmp:
        root = Path(tmp)
        replacement = root / audit.LOCK
        replacement.parent.mkdir(parents=True, exist_ok=True)
        replacement.write_bytes(authentic + b" ")
        assert git_blob_sha(replacement.read_bytes()) != audit.LOCK_BLOB
        try:
            audit.frozen(root)
        except audit.ComparabilityError as error:
            assert "changed" in str(error)
        else:
            raise AssertionError("tampered Git source lock was accepted")
    print("PASS: CONSTRUCTED one-byte source-lock change is rejected fail-closed")
    print("PASS: Real locked source file remained untouched")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--challenge", choices=("direct-vs-routed", "tampered-lock"),
                        required=True)
    name = parser.parse_args().challenge
    if name == "direct-vs-routed":
        direct_vs_routed()
    else:
        tampered_lock()


if __name__ == "__main__":
    main()
