"""Phase 3I strict provenance and no-label tests. Actual pip installs run in GitHub Actions."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from falsum.real_fix_corpus import load_queue
from falsum.phase3i_requests_runtime import (
    ADVISORY, CASE, CVE, EXPECTED, FIX_COMMIT, SCENARIOS, SOURCE_BLOB,
    STATUS, TEST_BLOB, BoundaryError, compare, pin_queue, run, validate_report,
    write_new,
)

ROOT = Path(__file__).resolve().parents[1]


def example(version):
    return {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "case_id": CASE, "advisory": ADVISORY, "cve": CVE,
        "pinned_upstream_fix_commit": FIX_COMMIT,
        "pinned_source_blob_sha1": SOURCE_BLOB, "pinned_regression_test_blob_sha1": TEST_BLOB,
        "actual_requests_version": version,
        "actual_installed_source_sha256": ("a" if version == "2.30.0" else "b") * 64,
        "source_file_outside_repo": True, "actual_library_method_executed": True,
        "version_appropriate_fix_condition_present": True,
        "no_socket_or_http_transport": True, "only_synthetic_proxy_auth": True,
        "real_credentials_used": 0, "real_application_executed": False,
        "trust_environment_disabled": True,
        "observations": [
            {"case": name, "url_scheme": scheme, "proxy_kind": kind,
             "preexisting_fake_auth_header": seeded,
             "proxy_authorization_header_after_rebuild": EXPECTED[version][i],
             "observed_header_matches_fake_proxy_credentials": EXPECTED[version][i],
             "returned_proxy_configuration_preserved": True}
            for i, (name, scheme, kind, seeded) in enumerate(SCENARIOS)
        ],
        "model_scored": False, "independently_approved_labels": 0,
        "accepted_training_pairs": 0, "accepted_anjoman_rows": 0,
        "network_eligible": False, "evaluator_registered": False,
    }


class RequestsRealRuntimeTests(unittest.TestCase):
    def test_prior_upstream_source_and_regression_test_pins(self):
        row = pin_queue(ROOT / "data/real-fix-queue.json")
        self.assertEqual(row["commit"], FIX_COMMIT)
        self.assertEqual(row["source_blob"], SOURCE_BLOB)
        self.assertEqual(row["test_blob"], TEST_BLOB)

    def test_tampered_pinned_queue_fails_closed(self):
        for key in ("repository", "commit", "source_blob", "test_blob", "advisory", "cve"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                q = load_queue(ROOT / "data/real-fix-queue.json")
                row = next(c for c in q["cases"] if c["id"] == CASE)
                row[key] = "f"*40 if key in ("commit","source_blob","test_blob") else "invalid"
                p = Path(directory)/"queue.json"
                p.write_text(json.dumps(q))
                with self.assertRaises((BoundaryError, ValueError)):
                    pin_queue(p)

    def test_historical_runtime_differences_and_controls(self):
        for version in EXPECTED:
            with self.subTest(version=version):
                validate_report(example(version))
        result = compare(example("2.30.0"), example("2.31.0"))
        self.assertTrue(result["historical_https_proxy_header_before"])
        self.assertFalse(result["https_proxy_header_after_fix"])
        self.assertTrue(result["stable_http_credentialed_proxy_header"])
        self.assertEqual(result["stable_other_negative_controls"], 3)
        self.assertEqual(result["outbound_network_calls"], 0)
        self.assertFalse(result["model_scored"])

    def test_swapped_releases_or_same_version_cannot_compare(self):
        for before, after in (("2.31.0","2.30.0"),("2.30.0","2.30.0")):
            with self.subTest(pair=(before,after)), self.assertRaises(BoundaryError):
                compare(example(before), example(after))

    def test_identical_source_files_refused(self):
        x,y=example("2.30.0"),example("2.31.0")
        y["actual_installed_source_sha256"]=x["actual_installed_source_sha256"]
        with self.assertRaises(BoundaryError):
            compare(x,y)

    def test_changed_or_omitted_controls_rejected(self):
        for i in range(len(SCENARIOS)):
            with self.subTest(case=SCENARIOS[i][0]):
                d=example("2.30.0")
                d["observations"][i]["proxy_authorization_header_after_rebuild"]=not EXPECTED["2.30.0"][i]
                with self.assertRaises(BoundaryError):
                    validate_report(d)
        d=example("2.31.0")
        d["observations"].pop()
        with self.assertRaises(BoundaryError):
            validate_report(d)

    def test_additional_fake_success_row_rejected(self):
        d=example("2.30.0")
        d["observations"].append(d["observations"][0])
        with self.assertRaises(BoundaryError):
            validate_report(d)

    def test_historical_source_and_test_pins_cannot_be_forged(self):
        for key in ("pinned_upstream_fix_commit", "pinned_source_blob_sha1",
                    "pinned_regression_test_blob_sha1"):
            with self.subTest(field=key):
                d=example("2.31.0")
                d[key]="f"*40
                with self.assertRaises(BoundaryError):validate_report(d)

    def test_no_human_review_or_network_acceptance_promotion(self):
        for key,value in (
            ("independently_approved_labels",1),
            ("accepted_training_pairs",1),
            ("accepted_anjoman_rows",1),
            ("evaluator_registered",True),
            ("network_eligible",True),
            ("model_scored",True),
            ("no_socket_or_http_transport",False),
            ("real_credentials_used",1),
            ("real_application_executed",True),
            ("trust_environment_disabled",False),
            ("actual_library_method_executed",False),
        ):
            with self.subTest(key=key):
                d=example("2.31.0")
                d[key]=value
                with self.assertRaises(BoundaryError):validate_report(d)

    def test_unsupported_runtime_refused_pre_import(self):
        with self.assertRaises(BoundaryError):
            run("2.32.0", ROOT/"data/real-fix-queue.json", ROOT)

    def test_bad_source_digest_and_version_not_trusted(self):
        for key,value in (
            ("actual_installed_source_sha256","xyz"*20+"1234"),
            ("actual_requests_version","2.32.0"),
        ):
            with self.subTest(key=key):
                d=example("2.31.0");d[key]=value
                with self.assertRaises(BoundaryError):validate_report(d)

    def test_all_report_fields_are_bounded_and_specific(self):
        d=example("2.31.0")
        d["extra_fact_claim"]="a production app was attacked"
        with self.assertRaises(BoundaryError):validate_report(d)
        d.pop("extra_fact_claim")
        d["observations"][0]["url_scheme"]="http"
        with self.assertRaises(BoundaryError):validate_report(d)

    def test_no_overwriting_existing_historical_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            file=Path(root)/"evidence.json"
            write_new(file,example("2.30.0"))
            original=file.read_bytes()
            with self.assertRaises(BoundaryError):write_new(file,example("2.31.0"))
            self.assertEqual(file.read_bytes(),original)


if __name__=="__main__":
    unittest.main()
