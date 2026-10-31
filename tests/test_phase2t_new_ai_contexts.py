"""AI-created training-candidate contexts are NOT independently valid training labels."""
import copy
import json
import unittest
from pathlib import Path
from falsum.ai_review_benchmark import AIReviewError, validate_specs
from falsum.real_fix_corpus import load_queue
from falsum.phase2t_project_isolation import validate_pools

ROOT=Path(__file__).resolve().parents[1]


class NewContextStudyTests(unittest.TestCase):
    def setUp(self):
        self.specs=json.loads((ROOT/"data/ai-review-train-candidate-drafts.json").read_text(encoding="utf-8"))
        self.train=load_queue(ROOT/"data/real-fix-train-candidates.json")
        self.old=load_queue(ROOT/"data/real-fix-queue.json")
        self.old_spec=json.loads((ROOT/"data/ai-review-drafts.json").read_text(encoding="utf-8"))

    def test_new_research_contexts_are_project_disjoint_and_not_training(self):
        self.assertEqual(len(validate_specs(self.specs,self.train)),4)
        report=validate_pools(self.train,self.old)
        self.assertTrue(report["project_separation_verified"])
        self.assertEqual(self.specs["independent_human_reviews"],0)
        self.assertIs(self.specs["model_training_authorized"],False)
        self.assertIs(self.specs["network_eligible"],False)
        self.assertEqual(len(self.old_spec["cases"]),4)
        self.assertFalse({r["id"] for r in self.specs["cases"]}&
                         {r["id"] for r in self.old_spec["cases"]})
        self.assertFalse({r["id"] for r in self.specs["cases"]}&
                         {r["id"] for r in self.old["cases"]})

    def test_four_new_families_all_reverse_proposals(self):
        for item in self.specs["cases"]:
            self.assertEqual(len(item["scenarios"]),2)
            self.assertEqual(
                [x["proposed_preferred"] for x in item["scenarios"]],
                ["finding","conditional"])
            self.assertEqual(len({x["facts"] for x in item["scenarios"]}),2)

    def test_spoofed_human_review_is_rejected(self):
        for field,value in (("independent_human_reviews",3),
                            ("model_training_authorized",True),
                            ("network_eligible",True)):
            with self.subTest(field=field):
                s=copy.deepcopy(self.specs)
                s[field]=value
                with self.assertRaises(AIReviewError):
                    validate_specs(s,self.train)

    def test_old_project_replacement_not_allowed(self):
        s=copy.deepcopy(self.specs)
        s["cases"][0]["id"]=self.old["cases"][0]["id"]
        with self.assertRaisesRegex(AIReviewError,"ordering"):
            validate_specs(s,self.train)


if __name__=="__main__":
    unittest.main()
