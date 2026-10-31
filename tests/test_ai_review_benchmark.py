"""Offline adversarial Phase 2S benchmark tests; never expert validation."""
import copy
import hashlib
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.ai_review_benchmark import (
    AIReviewError, STATUS, build, token_audit, validate_specs,
)
from falsum.real_fix_corpus import load_queue

ROOT = Path(__file__).resolve().parents[1]


def sample():
    specs = json.loads((ROOT / "data/ai-review-drafts.json").read_text(encoding="utf-8"))
    queue = load_queue(ROOT / "data/real-fix-queue.json")
    report = {
        "status": "SOURCE_VERIFIED_LABELS_UNREVIEWED",
        "source_verified": len(queue["cases"]),
        "independent_human_reviews": 0, "network_eligible": False,
        "training_authorized": False, "cases_sha256": "abc" * 21 + "a",
        "cases": [{"id": c["id"]} for c in queue["cases"]],
    }
    source_prompts = []
    refs = []
    for i, c in enumerate(queue["cases"]):
        ident = "verified-" + str(i)
        lang = "javascript" if c["repository"] == "axios/axios" else "python"
        source_prompts.append({"challenge_id": ident,
             "prompt": "Review the following original code excerpt for concrete security concerns.\n"
                       "Source excerpt:\n" + chr(96)*3 + lang + "\n"
                       "def source_stub(arg):\n    return arg\n" + chr(96)*3})
        refs.append({"challenge_id": ident, "case_id": c["id"],
                     "source_lines": [42, 44]})
        if c["repository"] == "pallets/jinja":
            source_prompts.append({"challenge_id": ident+"-real", "prompt":
              "Review the following original code excerpt for concrete security concerns.\n"
              "Source excerpt:\n" + chr(96)*3 + "python\n"
              "def do_attr(value):\n    return value.format\n" + chr(96)*3})
            refs.append({"challenge_id": ident+"-real", "case_id": c["id"],
                         "source_lines": [1412, 1438]})
    return specs, queue, report, ({"prompts": source_prompts}, {"records": refs})


class AIReviewTests(unittest.TestCase):
    def setUp(self):
        self.specs, self.queue, self.report, self.prompt_data = sample()

    def _build(self):
        with patch("falsum.ai_review_benchmark.build_challenges", return_value=self.prompt_data):
            return build(self.specs, self.queue, self.report)

    def test_specs_are_valid_drafts_and_not_human_review(self):
        records = validate_specs(self.specs, self.queue)
        self.assertEqual(len(records), 4)
        self.assertIs(self.specs["model_training_authorized"], False)
        self.assertEqual(self.specs["independent_human_reviews"], 0)

    def test_eight_examples_four_actual_source_projects(self):
        pub, key = self._build()
        self.assertEqual(len(pub["cases"]), 8)
        self.assertEqual(len(key["entries"]), 8)
        self.assertEqual(pub["status"], STATUS)
        self.assertFalse(pub["sealed_holdout"])
        self.assertFalse(pub["network_eligible"])
        self.assertFalse(pub["model_training_authorized"])
        self.assertEqual(pub["human_reviews"], 0)
        self.assertEqual(key["human_reviews"], 0)
        self.assertEqual(key["source_cases_sha256"], self.report["cases_sha256"])
        self.assertTrue(all(set(row) == {"case_id", "question", "candidate_a", "candidate_b"}
                            for row in pub["cases"]))
        self.assertTrue(all("GHSA-" not in row["question"] and
                            "CVE-" not in row["question"] for row in pub["cases"]))
        for row in key["entries"]:
            self.assertFalse(row["human_validated"])
            self.assertFalse(row["eligible"])
            self.assertEqual(row["research_provenance"],
                             "AI_AUTHORED_HYPOTHETICAL_CONTEXT_NOT_HUMAN_REVIEWED")

    def test_exact_context_reversal_with_identical_candidate_essays(self):
        pub, key = self._build()
        for i in range(0, 8, 2):
            left, right = pub["cases"][i:i+2]
            a, b = key["entries"][i:i+2]
            self.assertEqual({left["candidate_a"], left["candidate_b"]},
                             {right["candidate_a"], right["candidate_b"]})
            winning = lambda c, k: c["candidate_a"] if k["proposed_preferred"] == "A" else c["candidate_b"]
            self.assertNotEqual(winning(left, a), winning(right, b))
            self.assertEqual(left["question"].split("Deployment evidence")[0],
                             right["question"].split("Deployment evidence")[0])
            self.assertNotEqual(left["question"], right["question"])

    def test_private_key_never_appears_in_model_question_packet(self):
        pub, key = self._build()
        public = json.dumps(pub)
        self.assertNotIn("proposed_preferred", public)
        self.assertNotIn("source_commit", public)
        self.assertNotIn("advisory_url", public)
        self.assertNotIn("AI_PROPOSED_ANSWER_KEY", public)
        self.assertIn("proposed_preferred", json.dumps(key))

    def test_jinja_uses_actual_function_not_import_stub(self):
        pub, _ = self._build()
        jinja = [r for r in pub["cases"] if r["case_id"].startswith("real-jinja-")]
        self.assertEqual(len(jinja), 2)
        self.assertTrue(all("def do_attr(" in r["question"] for r in jinja))

    def test_refuse_review_or_eligible_promotion(self):
        for field, new in (("independent_human_reviews", 1), ("model_training_authorized", True),
                           ("network_eligible", True), ("research_only", False),
                           ("status", "INDEPENDENT_EXPERT_APPROVED")):
            with self.subTest(field=field):
                draft = copy.deepcopy(self.specs)
                draft[field] = new
                with self.assertRaises(AIReviewError):
                    validate_specs(draft, self.queue)

    def test_reject_cross_project_label_mixup(self):
        specs = copy.deepcopy(self.specs)
        specs["cases"][0]["id"], specs["cases"][1]["id"] = (
            specs["cases"][1]["id"], specs["cases"][0]["id"])
        with self.assertRaisesRegex(AIReviewError, "ordering"):
            validate_specs(specs, self.queue)

    def test_reject_missing_scenario_or_repeated_context(self):
        for action in ("remove", "repeat"):
            with self.subTest(action=action):
                draft = copy.deepcopy(self.specs)
                if action == "remove":
                    draft["cases"][0]["scenarios"].pop()
                else:
                    draft["cases"][0]["scenarios"][1]["facts"] = (
                        draft["cases"][0]["scenarios"][0]["facts"])
                with self.assertRaises(AIReviewError):
                    validate_specs(draft, self.queue)

    def test_reject_reused_answers_or_answer_length_shortcuts(self):
        draft = copy.deepcopy(self.specs)
        draft["cases"][1]["finding_answer"] = draft["cases"][0]["finding_answer"]
        with self.assertRaises(AIReviewError):
            validate_specs(draft, self.queue)
        draft = copy.deepcopy(self.specs)
        draft["cases"][0]["conditional_answer"] = "One sentence."
        with self.assertRaises(AIReviewError):
            validate_specs(draft, self.queue)

    def test_reject_advisory_answers_or_external_link_in_question(self):
        draft = copy.deepcopy(self.specs)
        draft["cases"][0]["finding_answer"] += " CVE-2023-32681"
        with self.assertRaisesRegex(AIReviewError, "advisory"):
            validate_specs(draft, self.queue)
        draft = copy.deepcopy(self.specs)
        draft["cases"][0]["scenarios"][0]["facts"] += " https://github.com/a"
        with self.assertRaisesRegex(AIReviewError, "advisory"):
            validate_specs(draft, self.queue)

    def test_reject_inconsistent_real_source_report(self):
        self.report["network_eligible"] = True
        with self.assertRaisesRegex(AIReviewError, "inconsistent"):
            self._build()
        self.report["network_eligible"] = False
        self.report["source_verified"] = 3
        with self.assertRaisesRegex(AIReviewError, "inconsistent"):
            self._build()

    def test_token_budget_uses_full_prompt_and_both_candidates(self):
        pub, _ = self._build()
        res = token_audit(pub, lambda text: [1] * min(512, len(text)//10))
        self.assertEqual(res["checked_pairs"], 8)
        self.assertEqual(res["model_inputs_checked"], 16)
        self.assertFalse(res["model_accuracy_measured"])
        self.assertTrue(res["all_pass"])
        self.assertEqual(res["human_reviews"], 0)

    def test_token_budget_fails_closed_on_513_tokens(self):
        pub, _ = self._build()
        report = token_audit(pub, lambda text: [1] * 513)
        self.assertFalse(report["all_pass"])
        self.assertEqual(len(report["failures"]), 8)
        self.assertEqual(report["model_inputs_checked"], 16)

    def test_tokenizer_cannot_insert_fake_ids(self):
        pub, _ = self._build()
        for invalid in ([True], [-1], [], None, ("1",)):
            with self.subTest(invalid=invalid), self.assertRaises(AIReviewError):
                token_audit(pub, lambda _: invalid)


if __name__ == "__main__":
    unittest.main()
