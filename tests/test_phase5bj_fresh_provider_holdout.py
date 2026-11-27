"""Adversarial contract tests for the frozen public-provider holdout."""
from __future__ import annotations

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

from falsum import phase5bj_fresh_provider_holdout as m
from falsum.phase4l_external_receipt_evidence import git_blob_sha


def advisory(events, *, package="Django", ecosystem="PyPI", identifier="GHSA-test-test-test"):
    return {
        "id": identifier,
        "affected": [{
            "package": {"ecosystem": ecosystem, "name": package},
            "ranges": [{"type": "ECOSYSTEM", "events": events}],
        }],
        "aliases": [],
        "database_specific": {"github_reviewed": True},
    }


class FreshProviderHoldoutContract(unittest.TestCase):
    def test_protocol_is_still_the_pre_observation_freeze(self):
        protocol = m.frozen_protocol()
        self.assertEqual(protocol["status"], "PHASE5BJ_FRESH_PUBLIC_PROVIDER_HOLDOUT_FROZEN_BEFORE_OBSERVATION")
        self.assertEqual(git_blob_sha((m.ROOT / m.PROTOCOL).read_bytes()), m.PROTOCOL_BLOB)
        self.assertEqual(list(m.SELECTED), [
            "test/fixtures/miner-responses/SECURITY_REVIEW/190048-pypi-django-3.2.0-200-paid.json",
            "test/fixtures/miner-responses/SECURITY_REVIEW/77010-npm-lodash-4.18.1-200-paid.json",
        ])

    def test_falsum_is_fail_closed_on_unsupported_range_and_honors_boundaries(self):
        target = {"ecosystem": "PyPI", "package": "django", "version": "3.2.13"}
        fixed = advisory([{"introduced": "3.2"}, {"fixed": "3.2.13"}])
        self.assertEqual(m.falsum_status(fixed, target), m.INAPPLICABLE)
        last = advisory([{"introduced": "3.2"}, {"last_affected": "3.2.13"}])
        self.assertEqual(m.falsum_status(last, target), m.APPLICABLE)
        unsupported = advisory([{"introduced": "3.2"}, {"fixed": "3.2.13-beta1"}])
        self.assertEqual(m.falsum_status(unsupported, target), m.UNKNOWN)

    def test_competent_baseline_is_version_aware_not_accept_all(self):
        target = {"ecosystem": "PyPI", "package": "django", "version": "3.2.20"}
        fixed = advisory([{"introduced": "3.2"}, {"fixed": "3.2.13"}])
        self.assertEqual(m.baseline_status(fixed, target), m.INAPPLICABLE)
        self.assertNotEqual(m.baseline_status(fixed, target), m.APPLICABLE)
        self.assertEqual(m.baseline_status(advisory([{"introduced": "3.2"}]), target), m.APPLICABLE)

    def test_pypi_name_canonicalization_does_not_break_exact_target_binding(self):
        target = {"ecosystem": "PyPI", "package": "django", "version": "3.2.0"}
        source = advisory([{"introduced": "3.2"}, {"fixed": "3.2.13"}], package="Django")
        self.assertEqual(m.falsum_status(source, target), m.APPLICABLE)
        self.assertEqual(m.baseline_status(source, target), m.APPLICABLE)

    def test_provider_capture_does_not_return_sensitive_body_fields(self):
        path = next(path for path in m.SELECTED if "77010" in path)
        raw_object = {
            "request": {"method": "GET", "endpoint": "/query", "payload": {"pkg": "lodash", "ver": "4.18.1"}},
            "status": 200, "paid": True, "charged": True,
            "body": {"miner_id": "77010", "result": {
                "package": {"name": "lodash", "system": "npm"},
                "version": {"version": "4.18.1", "advisories": []},
            }},
            "payment": {"secret": "must-not-escape"}, "receipt": {"token": "must-not-escape"},
            "bodyText": "must-not-escape",
        }
        raw = (json.dumps(raw_object, separators=(",", ":")) + "\n").encode()
        expected = m.SELECTED[path]
        with patch.dict(m.SELECTED, {path: git_blob_sha(raw)}):
            capture = m._provider_capture(path, raw)
        self.assertNotIn("payment", capture)
        self.assertNotIn("receipt", capture)
        self.assertNotIn("bodyText", capture)
        self.assertEqual(capture["reported_reference_ids"], [])
        self.assertEqual(m.SELECTED[path], expected)

    def test_provider_result_must_bind_to_request_target(self):
        path = next(path for path in m.SELECTED if "77010" in path)
        raw_object = {
            "request": {"method": "GET", "endpoint": "/query", "payload": {"pkg": "lodash", "ver": "4.18.1"}},
            "status": 200, "paid": True, "charged": True,
            "body": {"miner_id": "77010", "result": {
                "package": {"name": "other-package", "system": "npm"},
                "version": {"version": "4.18.1", "advisories": []},
            }},
        }
        raw = (json.dumps(raw_object, separators=(",", ":")) + "\n").encode()
        with patch.dict(m.SELECTED, {path: git_blob_sha(raw)}):
            with self.assertRaises(m.HoldoutError):
                m._provider_capture(path, raw)

    def test_non_reviewed_source_is_rejected_before_policy_evaluation(self):
        identifier = "GHSA-aaaa-bbbb-cccc"
        source = advisory([{"introduced": "3.2"}, {"fixed": "3.2.13"}], identifier=identifier)
        source["database_specific"]["github_reviewed"] = False
        raw = (json.dumps(source, separators=(",", ":")) + "\n").encode()
        source_spec = {identifier: ("advisories/github-reviewed/test.json", git_blob_sha(raw))}
        with patch.dict(m.SOURCE_SPECS, source_spec, clear=True):
            with self.assertRaises(m.HoldoutError):
                m._load_sources(lambda _url, **_kwargs: raw)

    def test_unknown_reference_is_not_promoted_by_the_report_reducer(self):
        capture = {
            "path": "fresh.json", "provider_blob_sha1": "a" * 40, "miner_id": "x",
            "target": {"ecosystem": "PyPI", "package": "django", "version": "3.2.0"},
            "reported_reference_ids": ["PYSEC-unknown"], "structural_paid_http200": True,
        }
        report = m._evaluate_capture(capture, {})
        self.assertEqual(report["falsum_counts"][m.APPLICABLE], 0)
        self.assertEqual(report["falsum_counts"][m.UNKNOWN], 1)
        self.assertEqual(report["baseline_counts"][m.UNKNOWN], 1)


if __name__ == "__main__":
    unittest.main()
