"""Phase 5AA unit tests: constructed tampering attempts, not external evidence."""
from __future__ import annotations

import base64
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase5aa_offline_reviewed_bundle as bundle
from falsum import phase5z_reviewed_advisory_consumption as gate
from falsum.phase5y_original_reviewed_version_applicability import frozen


def crafted_bundle() -> dict:
    """Deliberately FAKE documents, which must always fail SHA verification."""
    specs = frozen()["original_advisory_sources"]
    return {
        "schema_version": 1,
        "status": bundle.STATUS,
        "original_source_repository": bundle.ADVISORY_REPO,
        "original_source_commit": bundle.ADVISORY_COMMIT,
        "historical_target": bundle.TARGET,
        "original_reviewed_source_count": 6,
        "contains_external_miner_response_bodies": False,
        "current_advisory_freshness_verified": False,
        "approved_security_decision": False,
        "network_evaluator_registered": False,
        "original_reviewed_source_bytes_base64": {
            s["id"]: base64.b64encode(b'{"fabricated":true}').decode("ascii")
            for s in specs
        },
    }


class OfflineBundleAdversarial(unittest.TestCase):
    def setUp(self):
        self.context = tempfile.TemporaryDirectory()
        self.addCleanup(self.context.cleanup)
        self.file = Path(self.context.name) / "bundle.json"

    def write(self, obj):
        self.file.write_text(json.dumps(obj), encoding="utf-8")

    def assert_rejected(self, obj):
        self.write(obj)
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)

    def test_fabricated_source_bytes_with_plausible_manifest_cannot_pass(self):
        self.assert_rejected(crafted_bundle())

    def test_wrong_commit_target_security_claim_and_coverage_fail_closed(self):
        for name, value in (
            ("original_source_commit", "0" * 40),
            ("original_source_repository", "attacker/advisory-database"),
            ("historical_target", {"ecosystem": "npm", "package": "lodash",
                                   "version": "4.17.16"}),
            ("original_reviewed_source_count", 5),
            ("contains_external_miner_response_bodies", True),
            ("current_advisory_freshness_verified", True),
            ("approved_security_decision", True),
            ("network_evaluator_registered", True),
        ):
            with self.subTest(field=name):
                data = crafted_bundle()
                data[name] = value
                self.assert_rejected(data)

    def test_missing_extra_and_duplicate_source_ids_fail_closed(self):
        first = next(iter(crafted_bundle()["original_reviewed_source_bytes_base64"]))
        data = crafted_bundle()
        del data["original_reviewed_source_bytes_base64"][first]
        self.assert_rejected(data)
        data = crafted_bundle()
        data["original_reviewed_source_bytes_base64"]["GHSA-FAKE-FAKE-FAKE"] = "e30="
        self.assert_rejected(data)
        data = crafted_bundle()
        data["unknown_attestation"] = "verified"
        self.assert_rejected(data)

    def test_base64_noncanonical_empty_and_oversized_refused(self):
        first = next(iter(crafted_bundle()["original_reviewed_source_bytes_base64"]))
        for malformed in ("", "!!!", " e30=", "e30=\n", "e30", "A" * 270001):
            with self.subTest(malformed=malformed[:20]):
                data = crafted_bundle()
                data["original_reviewed_source_bytes_base64"][first] = malformed
                self.assert_rejected(data)

    def test_duplicate_json_keys_and_nonjson_are_refused(self):
        self.file.write_text('{"status":"first","status":"second"}')
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)
        self.file.write_text('{"broken":')
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)

    def test_empty_oversized_and_symlink_source_files_are_refused(self):
        self.file.write_bytes(b"")
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)
        self.file.write_bytes(b"x" * (bundle.MAX_BUNDLE_BYTES + 1))
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)
        target = Path(self.context.name) / "target.json"
        target.write_text(json.dumps(crafted_bundle()))
        self.file.unlink()
        self.file.symlink_to(target)
        with self.assertRaises(ValueError):
            bundle.load_bundle(self.file)

    def test_export_never_emits_a_bundle_from_modified_upstream_bytes(self):
        with self.assertRaises(ValueError):
            bundle.build_bundle(download=lambda url: b'{"id":"forged"}')

    def test_offline_option_without_real_local_request_is_rejected(self):
        # The existing original-source study must not silently claim an
        # offline original Miner replay using only six reviewed source docs.
        self.write(crafted_bundle())
        with self.assertRaises(SystemExit) as result:
            gate.main(["--reviewed-bundle", str(self.file),
                       "--out", str(Path(self.context.name) / "result.json")])
        self.assertEqual(result.exception.code, 1)

    def test_offline_bundle_is_not_a_spoofed_original_miner_receipt(self):
        self.write(crafted_bundle())
        request = Path(self.context.name) / "request.json"
        response = Path(self.context.name) / "response.json"
        request.write_text('{"method":"GET","endpoint":"/query","payload":{"pkg":"lodash","ver":"4.17.15"}}')
        response.write_text('{"miner_id":"77010","result_shape":"raw","result":{}}')
        with self.assertRaises(SystemExit) as result:
            gate.main(["--reviewed-bundle", str(self.file),
                       "--role", "direct_deps_dev_version",
                       "--request-json", str(request),
                       "--response-json", str(response),
                       "--out", str(Path(self.context.name) / "result.json")])
        self.assertEqual(result.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
