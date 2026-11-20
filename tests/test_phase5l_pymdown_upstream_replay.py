"""Adversarial receipt-schema tests, NOT actual upstream test execution.

The real upstream code and original security regression execute only in the
dedicated GitHub Actions jobs. These synthetic fixtures cannot establish that
any third-party Git revision, test or process actually ran.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from falsum import phase5l_pymdown_upstream_replay as test

ROOT = Path(__file__).resolve().parents[1]


def fake_log(stage: str) -> bytes:
    if stage == "parent-regression":
        return (
            b"FAILED tests/test_extensions/test_snippets.py::"
            b"TestSnippetsNested::test_restricted_directory_traversal - "
            b"AssertionError: SnippetMissingError not raised\n1 failed in 0.16s\n"
        )
    return b". [100%]\n1 passed in 0.14s\n"


def fake_record(lock: dict, stage: str, runtime: str) -> tuple[dict, bytes]:
    commit, source_sha, overlay, _ = test.expected(stage, lock)
    log = fake_log(stage)
    return {
        "schema_version": 1,
        "status": test.STATUS,
        "selection_lock_git_blob": test.LOCK_BLOB,
        "repository": lock["repository"],
        "advisory": lock["advisory"],
        "stage": stage,
        "python": runtime,
        "original_upstream_commit": commit,
        "source_blob_sha1": source_sha,
        "executed_original_upstream_test_blob_sha1": lock[
            "fixed_original_upstream_test_blob_sha1" if stage != "parent-original"
            else "parent_original_test_blob_sha1"
        ],
        "original_upstream_test_fixture_blob_sha1": (
            lock["fixed_original_upstream_fixture_blob_sha1"]
            if stage != "parent-original" else None
        ),
        "fixed_original_regression_test_overlaid_on_parent_only": overlay,
        "actual_pytest_subprocess_exit_code": (
            1 if stage == "parent-regression" else 0
        ),
        "actual_upstream_test_log_sha256": test.digest(log),
        "original_git_worktree_and_source_test_blobs_verified": True,
        "expected_original_assertion_failure_proven": stage == "parent-regression",
        "researcher_selected_not_external_holdout": True,
        "independent_human_appsec_gold_labels": 0,
        "trained_evaluator_scored": False,
        "telegraph_new_eligible_rows": 0,
        "official_h2_entry_submitted": False,
    }, log


class NewUpstreamPymdownSourceReplayProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock = test.load_lock(ROOT)

    def test_lock_committed_before_test_code_and_exact_original_git_blob(self):
        raw = (ROOT / test.LOCK_PATH).read_bytes()
        self.assertEqual(test.git_blob(raw), test.LOCK_BLOB)
        self.assertEqual(self.lock["original_fix_commit"],
                         "63b7835776d703d6c339cf2110d9888f676efc0c")
        self.assertEqual(self.lock["direct_vulnerable_parent"],
                         "3d185501daaa1424c4a8d42124112c44ef6ab635")
        self.assertEqual(self.lock["original_parent_source_blob_sha1"],
                         "305c7c0aae68516f4aad77c2430234762e981688")
        self.assertEqual(self.lock["original_fixed_source_blob_sha1"],
                         "b808d7b929fec0962c4b41ca0a70ed4e696d0fc5")
        self.assertTrue(self.lock["author_selected_public_historical_case_not_independent_review"])
        self.assertFalse(self.lock["trained_model_scored"])

    def test_selection_lock_mutation_refused_even_if_plausible(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / test.LOCK_PATH
            p.parent.mkdir(parents=True)
            original = (ROOT / test.LOCK_PATH).read_bytes()
            p.write_bytes(original.replace(b'"10.21.2"', b'"10.21.4"'))
            with self.assertRaisesRegex(test.ReplayError, "Git blob"):
                test.load_lock(Path(tmp))

    def test_upstream_fixed_and_parent_stage_git_requirements_are_distinct(self):
        for stage in test.STAGES:
            with self.subTest(stage=stage):
                commit, source, overlay, method = test.expected(stage,self.lock)
                self.assertIn("test_snippets.py::",method)
                self.assertEqual(
                    commit,
                    self.lock["original_fix_commit"] if stage == "fixed-regression"
                    else self.lock["direct_vulnerable_parent"]
                )
                self.assertEqual(
                    source,
                    self.lock["original_fixed_source_blob_sha1"]
                    if stage == "fixed-regression" else
                    self.lock["original_parent_source_blob_sha1"]
                )
                self.assertEqual(overlay,stage=="parent-regression")

    def test_real_execution_requires_actual_immutable_git_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            t=Path(tmp)
            with self.assertRaises(test.ReplayError):
                test.execute(t,self.lock,"fixed-regression","3.11",
                             t/"output.json",t/"log.txt")
            self.assertFalse((t/"output.json").exists())

    def test_local_synthetic_examples_validate_only_schema_not_live_execution(self):
        for runtime in test.RUNTIMES:
            for stage in test.STAGES:
                row,log=fake_record(self.lock,stage,runtime)
                with self.subTest(runtime=runtime,stage=stage):
                    test.verify_receipt(row,log,self.lock,stage=stage,
                                        python_version=runtime)

    def test_wrong_parent_failure_reason_or_missing_actual_assertion_is_rejected(self):
        good,log=fake_record(self.lock,"parent-regression","3.11")
        for bad_log in (
            b"1 failed in 0.13s: DependencyError\n",
            b"1 failed: ModuleNotFoundError: markdown\n",
            b"ERROR: collecting upstream test\n1 failed\n",
            b"1 skipped in 0.2s",
        ):
            with self.subTest(bad_log=bad_log),self.assertRaises(test.ReplayError):
                bad=dict(good,actual_upstream_test_log_sha256=test.digest(bad_log))
                test.verify_receipt(bad,bad_log,self.lock,stage="parent-regression",
                                    python_version="3.11")

    def test_original_parent_control_must_pass_not_be_skipped_or_fake_green(self):
        row,log=fake_record(self.lock,"parent-original","3.11")
        for bad_log in (b"1 skipped in 1s",b"no tests ran",b"1 failed in 1s"):
            with self.subTest(log=bad_log),self.assertRaises(test.ReplayError):
                t=dict(row,actual_upstream_test_log_sha256=test.digest(bad_log))
                test.verify_receipt(t,bad_log,self.lock,stage="parent-original",
                                    python_version="3.11")

    def test_forged_gold_model_h2_or_eligible_rows_cannot_pass_as_source_test_proof(self):
        src,log=fake_record(self.lock,"fixed-regression","3.11")
        mutations=[
            ("independent_human_appsec_gold_labels",1),
            ("trained_evaluator_scored",True),
            ("telegraph_new_eligible_rows",20),
            ("official_h2_entry_submitted",True),
            ("researcher_selected_not_external_holdout",False),
            ("original_git_worktree_and_source_test_blobs_verified",False),
            ("expected_original_assertion_failure_proven",True),
            ("selection_lock_git_blob","0"*40),
            ("source_blob_sha1","0"*40),
            ("original_upstream_commit","0"*40),
            ("executed_original_upstream_test_blob_sha1","0"*40),
            ("original_upstream_test_fixture_blob_sha1","0"*40),
            ("fixed_original_regression_test_overlaid_on_parent_only",True),
            ("actual_upstream_test_log_sha256","0"*64),
            ("schema_version",True),
            ("actual_pytest_subprocess_exit_code",True),
        ]
        for key,value in mutations:
            with self.subTest(key=key):
                edited=dict(src,**{key:value})
                with self.assertRaises(test.ReplayError):
                    test.verify_receipt(edited,log,self.lock,stage="fixed-regression",
                                        python_version="3.11")
        extra=dict(src,certified_expert_review=True)
        with self.assertRaises(test.ReplayError):
            test.verify_receipt(extra,log,self.lock,stage="fixed-regression",
                                python_version="3.11")

    def test_duplicate_json_keys_are_refused_not_silently_overridden(self):
        with self.assertRaises(test.ReplayError):
            test.read_json(b'{"status":"EXTERNAL_GOLD","status":"REAL_TEST"}')

    def write_all_synthetic_records(self,dir:Path):
        for runtime in test.RUNTIMES:
            for stage in test.STAGES:
                stem=f"phase5l-{stage}-PY{runtime}"
                target=dir/stem
                target.mkdir(parents=True)
                record,log=fake_record(self.lock,stage,runtime)
                (target/f"{stem}.json").write_text(json.dumps(record))
                (target/f"{stem}.log").write_bytes(log)

    def test_aggregate_six_synthetic_schema_fixtures_never_claims_independent_gold(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write_all_synthetic_records(root)
            x=test.aggregate(root,self.lock)
            self.assertEqual(x["actual_upstream_pytest_runs"],6)
            self.assertEqual(x["new_original_upstream_security_fix_stages"],1)
            self.assertEqual(x["original_source_fix_stages_including_this_separate_replay"],6)
            self.assertEqual(x["distinct_original_upstream_projects_including_this_case"],5)
            self.assertTrue(x["not_admitted_into_legacy_five_witness_checker"])
            self.assertEqual(x["independent_human_appsec_gold_labels"],0)
            self.assertFalse(x["blind_new_case_holdout"])
            self.assertFalse(x["trained_model_improvement_proven"])
            self.assertEqual(x["new_semantic_model_evaluations"],0)

    def test_aggregate_missing_or_corrupt_matrix_logs_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write_all_synthetic_records(root)
            target=root/"phase5l-parent-regression-PY3.11"/"phase5l-parent-regression-PY3.11.log"
            target.write_text("1 passed in 0.3s\n")
            with self.assertRaisesRegex(test.ReplayError,"receipt"):
                test.aggregate(root,self.lock)
            target.unlink()
            with self.assertRaisesRegex(test.ReplayError,"artifact missing"):
                test.aggregate(root,self.lock)

    def test_aggregate_refuses_fake_record_missing_one_python_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write_all_synthetic_records(root)
            p=root/"phase5l-fixed-regression-PY3.13"/"phase5l-fixed-regression-PY3.13.json"
            p.unlink()
            with self.assertRaises(test.ReplayError):
                test.aggregate(root,self.lock)

    def test_aggregate_command_cannot_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            self.write_all_synthetic_records(root)
            output=root/"aggregate.json"
            self.assertEqual(test.main(["aggregate","--artifacts-dir",str(root),
                                        "--out",str(output)]),0)
            self.assertEqual(json.loads(output.read_text())["new_semantic_model_evaluations"],0)
            with self.assertRaises(SystemExit):
                test.main(["aggregate","--artifacts-dir",str(root),
                           "--out",str(output)])


if __name__ == "__main__":
    unittest.main()
