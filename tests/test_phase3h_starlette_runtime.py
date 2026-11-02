"""Phase 3H offline adversarial report tests. Real framework runs in pinned CI matrix."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from falsum.phase3h_starlette_runtime import (
    CASE, CVE, ADVISORY, FIX_COMMIT, SOURCE_BLOB, TEST_BLOB, EXPECTED,
    STATUS, REQUESTS, RuntimeError3H, _write_new, compare,
    run_installed, validate_report, verify_source_queue,
)
from falsum.real_fix_corpus import load_queue

ROOT = Path(__file__).resolve().parents[1]


def sample(version):
    statuses = EXPECTED[version]
    return {
        "schema_version": 1, "status": STATUS, "intent": "SECURITY_REVIEW_GENERAL",
        "case_id": CASE, "advisory": ADVISORY, "cve": CVE,
        "upstream_fix_commit": FIX_COMMIT, "upstream_source_post_fix_blob": SOURCE_BLOB,
        "upstream_test_post_fix_blob": TEST_BLOB, "installed_version": version,
        "runtime_source_sha256": ("a" if version == "0.26.1" else "b") * 64,
        "runtime_source_outside_repo": True, "actual_installed_framework_executed": True,
        "lookup_path_boundary": "commonprefix" if version == "0.26.1" else "commonpath",
        "synthetic_fixtures_only": True, "in_process_no_network": True,
        "real_user_files_read": 0,
        "results": [
            {"name": name, "status": statuses[name],
             "matched_expected_fixture": statuses[name] == 200}
            for name, _ in REQUESTS
        ],
        "sameprefix_sibling_visible": version == "0.26.1",
        "controls_passed": True, "independent_human_labels": 0,
        "accepted_training_pairs": 0, "accepted_network_evaluation_rows": 0,
        "model_scored": False, "network_eligible": False, "evaluator_registered": False,
    }


class RealRuntimeEvidenceBoundaryTests(unittest.TestCase):
    def test_actual_historical_starlette_queue_is_pinned(self):
        row = verify_source_queue(ROOT / "data/real-fix-train-candidates.json")
        self.assertEqual(row["source_blob"], SOURCE_BLOB)
        self.assertEqual(row["test_blob"], TEST_BLOB)
        self.assertEqual(row["commit"], FIX_COMMIT)

    def test_bad_queue_source_or_test_identity_rejected(self):
        for key in ("commit", "repository", "source_blob", "test_blob", "advisory", "cve"):
            with self.subTest(field=key), tempfile.TemporaryDirectory() as d:
                queue = load_queue(ROOT / "data/real-fix-train-candidates.json")
                row = next(x for x in queue["cases"] if x["id"] == CASE)
                row[key] = "f" * 40 if key in ("commit", "source_blob", "test_blob") else "other"
                path = Path(d) / "tampered.json"
                path.write_text(json.dumps(queue))
                with self.assertRaises((RuntimeError3H, ValueError)):
                    verify_source_queue(path)

    def test_exact_controlled_four_observations_validate(self):
        for ver in EXPECTED:
            with self.subTest(version=ver):
                validate_report(sample(ver))

    def test_both_versions_must_have_opposite_real_boundaries(self):
        x = compare(sample("0.26.1"), sample("0.27.0"))
        self.assertTrue(x["controlled_sibling_visible_before"])
        self.assertTrue(x["controlled_sibling_blocked_after"])
        self.assertEqual(x["unchanged_safe_and_negative_controls"], 3)
        self.assertFalse(x["trained_model_tested"])
        self.assertFalse(x["network_eligible"])

    def test_swapped_version_input_rejected(self):
        with self.assertRaises(RuntimeError3H):
            compare(sample("0.27.0"), sample("0.26.1"))

    def test_same_version_forgery_rejected(self):
        with self.assertRaises(RuntimeError3H):
            compare(sample("0.26.1"), sample("0.26.1"))

    def test_source_file_sha_cannot_be_identical(self):
        old, fixed = sample("0.26.1"), sample("0.27.0")
        fixed["runtime_source_sha256"] = old["runtime_source_sha256"]
        with self.assertRaises(RuntimeError3H):
            compare(old, fixed)

    def test_changed_control_results_refused(self):
        for label in ("inside", "missing", "nonmatching_sibling", "sameprefix_sibling"):
            with self.subTest(label=label):
                old = sample("0.26.1")
                row = next(r for r in old["results"] if r["name"] == label)
                row["status"] = 404 if row["status"] == 200 else 200
                with self.assertRaises(RuntimeError3H):
                    validate_report(old)

    def test_no_model_promotion_no_fake_security_accuracy(self):
        for key, value in (
            ("network_eligible", True),
            ("evaluator_registered", True),
            ("model_scored", True),
            ("independent_human_labels", 1),
            ("accepted_training_pairs", 1),
            ("accepted_network_evaluation_rows", 1),
            ("real_user_files_read", 1),
            ("in_process_no_network", False),
            ("actual_installed_framework_executed", False),
        ):
            with self.subTest(field=key):
                report = sample("0.27.0")
                report[key] = value
                with self.assertRaises(RuntimeError3H):
                    validate_report(report)

    def test_source_and_regression_blob_mutation_fails(self):
        for key in ("upstream_fix_commit", "upstream_source_post_fix_blob", "upstream_test_post_fix_blob"):
            with self.subTest(field=key):
                report = sample("0.26.1")
                report[key] = "f" * 40
                with self.assertRaises(RuntimeError3H):
                    validate_report(report)

    def test_missing_or_extra_report_rows_rejected(self):
        for kind in ("remove", "duplicate", "extra"):
            with self.subTest(kind=kind):
                report = sample("0.26.1")
                if kind == "remove":
                    report["results"].pop()
                elif kind == "duplicate":
                    report["results"][1] = report["results"][0].copy()
                else:
                    report["results"].append(report["results"][-1].copy())
                with self.assertRaises(RuntimeError3H):
                    validate_report(report)

    def test_unknown_installed_release_cannot_be_accepted(self):
        with self.assertRaises(RuntimeError3H):
            validate_report({**sample("0.26.1"), "installed_version": "0.28.0"})

    def test_unapproved_release_rejected_before_runtime_import(self):
        with self.assertRaises(RuntimeError3H):
            run_installed("0.28.0", ROOT / "data/real-fix-train-candidates.json", ROOT)

    def test_report_does_not_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "source.json"
            _write_new(path, sample("0.27.0"))
            original = path.read_bytes()
            with self.assertRaises(RuntimeError3H):
                _write_new(path, sample("0.26.1"))
            self.assertEqual(path.read_bytes(), original)

    def test_nonhex_runtime_source_digests_rejected(self):
        report = sample("0.26.1")
        report["runtime_source_sha256"] = "x" * 64
        with self.assertRaises(RuntimeError3H):
            validate_report(report)

    def test_synthetic_good_report_is_not_claim_of_model_quality(self):
        report = sample("0.27.0")
        self.assertEqual(report["independent_human_labels"], 0)
        self.assertFalse(report["model_scored"])
        self.assertEqual(report["accepted_network_evaluation_rows"], 0)


if __name__ == "__main__":
    unittest.main()
