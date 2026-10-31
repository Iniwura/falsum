"""Adversarial project leakage tests: realistic source inventory, NOT independent ground truth."""
import copy
import unittest
from pathlib import Path

from falsum.phase2t_project_isolation import PartitionError, validate_pools
from falsum.real_fix_corpus import load_queue, RealFixError

ROOT=Path(__file__).resolve().parents[1]


class PoolIsolationTests(unittest.TestCase):
    def setUp(self):
        self.train=load_queue(ROOT/"data/real-fix-train-candidates.json")
        self.inspected=load_queue(ROOT/"data/real-fix-queue.json")

    def test_eight_distinct_projects_with_false_holdout_flags(self):
        report=validate_pools(self.train,self.inspected)
        self.assertEqual(report["splits"][0]["rows"],4)
        self.assertEqual(report["splits"][1]["rows"],4)
        self.assertEqual(report["human_approved_labels"],0)
        self.assertFalse(report["training_data_authorized"])
        self.assertFalse(report["evaluation_data_authorized"])
        self.assertFalse(report["network_eligible"])
        self.assertFalse(report["sealed_holdout"])
        self.assertFalse(report["source_verified_by_this_function"])
        self.assertEqual(report["splits"][1]["stage"],"PUBLICLY_INSPECTED_NOT_A_SEALED_HOLDOUT")
        self.assertEqual(len(set(report["splits"][0]["projects"]+report["splits"][1]["projects"])),8)

    def test_train_queue_and_original_diagnostic_queue_must_be_separate(self):
        with self.assertRaisesRegex(PartitionError,"repository"):
            validate_pools(self.inspected,self.inspected)

    def test_copied_inspected_project_by_case_rejected(self):
        train=copy.deepcopy(self.train)
        train["cases"][0]["repository"]=self.inspected["cases"][0]["repository"]
        with self.assertRaisesRegex(PartitionError,"repository"):
            validate_pools(train,self.inspected)

    def test_cross_split_advisory_reuse_rejected_even_when_project_differs(self):
        train=copy.deepcopy(self.train)
        train["cases"][0]["advisory"]=self.inspected["cases"][0]["advisory"]
        with self.assertRaisesRegex(PartitionError,"advisory"):
            validate_pools(train,self.inspected)

    def test_cross_split_commit_reuse_rejected(self):
        train=copy.deepcopy(self.train)
        train["cases"][0]["commit"]=self.inspected["cases"][0]["commit"]
        with self.assertRaisesRegex(PartitionError,"commit"):
            validate_pools(train,self.inspected)

    def test_cross_split_parent_source_blob_reuse_rejected(self):
        for field in ("parent","source_blob","test_blob"):
            with self.subTest(field=field):
                train=copy.deepcopy(self.train)
                train["cases"][0][field]=self.inspected["cases"][0][field]
                with self.assertRaisesRegex(PartitionError,field):
                    validate_pools(train,self.inspected)

    def test_no_live_label_or_eligible_status_promoted(self):
        for field,value in (("status","ACCEPTED_TRAINING_DATA"),("intent","CODE_REVIEW_GENERAL")):
            with self.subTest(field=field):
                train=copy.deepcopy(self.train)
                train[field]=value
                with self.assertRaises(PartitionError):
                    validate_pools(train,self.inspected)

    def test_central_advisory_is_exact_ghsa_not_fake_repository_advisory(self):
        self.assertTrue(any(r["public_source"].startswith("https://github.com/advisories/")
                            for r in self.train["cases"]))
        for replacement in (
            "https://github.com/advisories/GHSA-v5gw-mw7f-84px",
            "https://evil.example/advisories/GHSA-gwvm-45gx-3cf8",
            "https://github.com/other/repo/security/advisories/GHSA-gwvm-45gx-3cf8",
        ):
            draft=copy.deepcopy(self.train)
            draft["cases"][1]["public_source"]=replacement
            with self.assertRaisesRegex(RealFixError,"advisory URL"):
                from tempfile import TemporaryDirectory
                import json
                with TemporaryDirectory() as d:
                    file=Path(d)/"bad.json"
                    file.write_text(json.dumps(draft))
                    load_queue(file)

    def test_cve_and_family_consistency_with_independent_sources(self):
        report=validate_pools(self.train,self.inspected)
        self.assertEqual(len(report["splits"][0]["cases"]),4)
        self.assertEqual(len(report["splits"][1]["cases"]),4)
        self.assertNotEqual(set(report["splits"][0]["cases"]),set(report["splits"][1]["cases"]))


if __name__=="__main__":
    unittest.main()
