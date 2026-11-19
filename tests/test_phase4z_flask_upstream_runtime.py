"""Phase 4Z integrity and falsification tests, not human gold or live source proof."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from falsum import phase4z_flask_upstream_runtime as p

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "data/phase4z-flask-new-source-lock.json"


def real_lock() -> dict:
    return json.loads(LOCK.read_text(encoding="utf-8"))


GOOD_LOGS = (
    "tests/test_basic.py::test_session_vary_cookie PASSED\n1 passed in 0.10s",
    "tests/test_basic.py::test_session_refresh_vary FAILED\n"
    "E KeyError: 'Vary'\n1 failed in 0.10s",
    "tests/test_basic.py::test_session_refresh_vary PASSED\n1 passed in 0.10s",
)


class FlaskSourceFirstSecurityCaseTests(unittest.TestCase):
    def test_researcher_selected_public_source_is_exact_upstream_single_parent_patch(self):
        doc = p.load_lock(LOCK.read_bytes())
        self.assertEqual(doc["repository"], "pallets/flask")
        self.assertEqual(doc["case_id"], "flask-session-cookie-vary")
        self.assertEqual(doc["fixed_commit"], "8705dd39c4fa563ea0fe0bf84c85da8fcc98b88d")
        self.assertEqual(doc["advisory"], "GHSA-m2qf-hxjv-5gpq")
        self.assertTrue(doc["facts"]["researcher_selected_not_external_independent"])
        self.assertTrue(doc["facts"]["no_blind_trained_model_holdout_claim"])
        self.assertEqual(doc["facts"]["independent_human_gold_labels"], 0)

    def test_tampered_source_test_advisory_or_direct_parent_pin_refused(self):
        for field in (
            "repository", "advisory", "fixed_commit", "direct_parent",
            "parent_source_blob", "fixed_source_blob",
            "parent_test_blob", "fixed_test_blob", "source_path",
            "test_path", "new_upstream_security_regression_selector",
        ):
            with self.subTest(field=field):
                doc = real_lock()
                doc[field] = "f" * 40
                with self.assertRaises(p.FlaskEvidenceError):
                    p.load_lock(json.dumps(doc).encode())

    def test_extra_pseudo_gold_or_forged_network_receipt_refused(self):
        bads = (
            lambda x: x["facts"].update(independent_human_gold_labels=1),
            lambda x: x["facts"].update(new_anjoman_evaluation_rows=5),
            lambda x: x["facts"].update(network_evaluator_registered=True),
            lambda x: x["facts"].update(researcher_selected_not_external_independent=False),
            lambda x: x.update(model_improvement_proven=True),
            lambda x: x.pop("test_path"),
        )
        for change in bads:
            with self.subTest(change=str(change)):
                doc = real_lock()
                change(doc)
                with self.assertRaises(p.FlaskEvidenceError):
                    p.load_lock(json.dumps(doc).encode())

    def test_expected_upstream_vary_cookie_assertion_failure_only(self):
        p.verify_log_evidence(*GOOD_LOGS, (0, 1, 0))

    def test_environment_error_cannot_pretend_to_be_expected_failing_regression(self):
        variants = (
            (GOOD_LOGS[0], "ModuleNotFoundError: No module named 'flask'", GOOD_LOGS[2]),
            (GOOD_LOGS[0], "tests/test_basic.py::test_session_refresh_vary FAILED\nImportError: missing pytest", GOOD_LOGS[2]),
            (GOOD_LOGS[0], "tests/test_basic.py::test_session_refresh_vary FAILED\nKeyError: 'OTHER'", GOOD_LOGS[2]),
            (GOOD_LOGS[0], "tests/test_basic.py::test_session_refresh_vary FAILED\nAssertionError: 1 != 2", GOOD_LOGS[2]),
            (GOOD_LOGS[0], GOOD_LOGS[1], "tests/test_basic.py::test_session_refresh_vary FAILED\n1 failed"),
        )
        for reports in variants:
            with self.subTest(report=reports[1][:70]), self.assertRaises(p.FlaskEvidenceError):
                p.verify_log_evidence(*reports, (0, 1, 0))

    def test_wrong_test_exit_states_not_accepted(self):
        for statuses in ((1, 1, 0), (0, 0, 0), (0, 1, 1), (0, 0, 1)):
            with self.subTest(exits=statuses), self.assertRaises(p.FlaskEvidenceError):
                p.verify_log_evidence(*GOOD_LOGS, statuses)

    def test_no_test_runner_receipt_from_forged_log_only(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, value in (
                ("parent-original", "0"), ("parent-regression", "1"),
                ("fixed-regression", "0"),
            ):
                (root / (name + ".exit")).write_text(value + "\n")
            self.assertEqual(p._exit(root / "parent-original.exit"), 0)
            (root / "parent-regression.exit").write_text("1;true\n")
            with self.assertRaises(p.FlaskEvidenceError):
                p._exit(root / "parent-regression.exit")

    def test_symlinked_and_oversized_untrusted_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            target = root / "big.log"
            target.write_bytes(b"x" * 1025)
            with self.assertRaises(p.FlaskEvidenceError):
                p.read(target, 1024)
            link = root / "symlink"
            link.symlink_to(target)
            with self.assertRaises(p.FlaskEvidenceError):
                p.read(link, 10_000)

    def test_git_blob_identifiers_use_exact_git_prefix(self):
        import hashlib
        raw = b"public fixture"
        expected = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        self.assertEqual(p.git_blob(raw), expected)
        self.assertNotEqual(p.git_blob(raw), p.sha(raw))

    def test_unchecked_source_paths_are_not_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with self.assertRaises(p.FlaskEvidenceError):
                p.inspect_tree(real_lock(), root, "parent", overlay=True)
            with self.assertRaises(p.FlaskEvidenceError):
                p.inspect_tree(real_lock(), root, "fixed", overlay=False)


if __name__ == "__main__":
    unittest.main()
