"""Prior-advisory exposure tests: avoid incorrectly claiming a clean holdout."""
import copy
import json
import unittest
from pathlib import Path
from falsum.phase2t_prior_exposure import ExposureError, audit
from falsum.real_fix_corpus import load_queue

ROOT=Path(__file__).resolve().parents[1]


class PriorExposureTests(unittest.TestCase):
    def setUp(self):
        self.prior=json.loads((ROOT/"data/advisory-queue.json").read_text(encoding="utf-8"))
        self.new=load_queue(ROOT/"data/real-fix-train-candidates.json")
        self.old=load_queue(ROOT/"data/real-fix-queue.json")

    def test_real_old_advisory_queue_contaminates_two_old_diagnostics(self):
        report=audit(self.prior,self.new,self.old)
        self.assertEqual(report["prior_advisory_count"],32)
        self.assertEqual(report["pools"][0]["exact_advisory_matches"],0)
        self.assertEqual(report["pools"][0]["project_package_overlap_count"],0)
        self.assertEqual(report["pools"][1]["exact_advisory_matches"],2)
        old_hits=[x for x in report["pools"][1]["records"] if x["advisory_id_seen_in_prior_queue"]]
        self.assertEqual({x["case_id"] for x in old_hits},
                         {"real-jinja-attr-sandbox","real-axios-absolute-baseurl"})
        self.assertTrue(all(x["exact_advisory_previous_split"]=="train" for x in old_hits))
        self.assertIs(report["heldout_sealed"],False)
        self.assertIs(report["model_accuracy_certified"],False)
        self.assertIs(report["network_eligible"],False)

    def test_reused_prior_advisory_cannot_be_mislabeled_new(self):
        new=copy.deepcopy(self.new)
        new["cases"][0]["advisory"]="GHSA-cpwx-vrp4-4pq7"
        report=audit(self.prior,new,self.old)
        self.assertEqual(report["pools"][0]["exact_advisory_matches"],1)

    def test_package_overlap_detected_without_exact_advisory(self):
        new=copy.deepcopy(self.new)
        new["cases"][0]["repository"]="pallets/jinja"
        report=audit(self.prior,new,self.old)
        self.assertEqual(report["pools"][0]["exact_advisory_matches"],0)
        self.assertEqual(report["pools"][0]["project_package_overlap_count"],1)

    def test_duplicate_historical_advisory_rejected(self):
        prior=copy.deepcopy(self.prior)
        prior["advisories"].append(copy.deepcopy(prior["advisories"][0]))
        with self.assertRaisesRegex(ExposureError,"duplicate"):
            audit(prior,self.new,self.old)

    def test_empty_or_forged_prior_rejected(self):
        for malformed in ({},{"schema_version":1,"advisories":[]},
                          {"schema_version":1,"advisories":"invented"}):
            with self.subTest(malformed=malformed),self.assertRaises(ExposureError):
                audit(malformed,self.new,self.old)

    def test_provenance_scope_is_precisely_limited(self):
        report=audit(self.prior,self.new,self.old)
        self.assertTrue(all(not r["case_is_new_to_complete_model"] for p in report["pools"]
                            for r in p["records"]))
        self.assertIn("NOT",report["warning"])
        self.assertEqual(len(report["pools"][0]["records"]),4)


if __name__=="__main__":
    unittest.main()
