"""Offline tests for the real tokenizer's strict model-input budget contract."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.prompt_token_budget import (
    MAX_TASK_TOKENS, TOKEN_LIMIT, ANSWER_RESERVE, BOUNDARY_RESERVE,
    TokenBudgetError, audit_prompts,
)


def source():
    return {
        "schema_version": 1,
        "status": "UNREVIEWED_PUBLIC_PRE_FIX_CHALLENGE_NO_ANSWERS",
        "intent": "SECURITY_REVIEW_GENERAL",
        "sealed_holdout": False,
        "model_training_authorized": False,
        "evaluation_authorized": False,
        "network_eligible": False,
        "independent_human_reviews": 0,
        "tokenizer_512_verified": False,
        "prompts": [{
            "challenge_id": "1abcdef000abcdef0000",
            "prompt": "Review the following original code excerpt for security. Source excerpt:\nline with code",
        }],
    }


class TokenBudgetTests(unittest.TestCase):
    def test_budget_has_answer_and_boundary_allowance(self):
        self.assertEqual(MAX_TASK_TOKENS + ANSWER_RESERVE + BOUNDARY_RESERVE, TOKEN_LIMIT)
        self.assertEqual(MAX_TASK_TOKENS, 384)

    def test_small_real_render_is_not_claimed_as_accuracy(self):
        report = audit_prompts(source(), lambda _: [12] * 128)
        self.assertTrue(report["all_pass"])
        self.assertEqual(report["passes"], 1)
        self.assertEqual(report["max_observed_task_tokens"], 128)
        self.assertFalse(report["network_eligible"])
        self.assertFalse(report["eval_accuracy_measured"])
        self.assertFalse(report["sealed_holdout"])

    def test_exact_cap_and_overflow(self):
        good = audit_prompts(source(), lambda _: [3] * MAX_TASK_TOKENS)
        self.assertTrue(good["all_pass"])
        bad = audit_prompts(source(), lambda _: [3] * (MAX_TASK_TOKENS + 1))
        self.assertFalse(bad["all_pass"])
        self.assertEqual(bad["failures"], ["1abcdef000abcdef0000"])

    def test_duplicate_case_ids_rejected(self):
        obj = source()
        obj["prompts"].append(obj["prompts"][0].copy())
        with self.assertRaisesRegex(TokenBudgetError, "duplicate"):
            audit_prompts(obj, lambda _: [1])

    def test_answer_key_leak_field_rejected(self):
        obj = source()
        obj["prompts"][0]["answer"] = "flag vulnerability"
        with self.assertRaisesRegex(TokenBudgetError, "non-prompt"):
            audit_prompts(obj, lambda _: [1])

    def test_non_finite_or_invalid_token_ids_rejected(self):
        for ids in (None, [True], [-1], ["1"], [], (1,2)):
            with self.subTest(ids=ids), self.assertRaises(TokenBudgetError):
                audit_prompts(source(), lambda _: ids)

    def test_wrong_model_flag_rejected(self):
        for key, value in [
            ("tokenizer_512_verified", True), ("network_eligible", True),
            ("model_training_authorized", True), ("sealed_holdout", True),
            ("evaluation_authorized", True), ("independent_human_reviews", 1),
        ]:
            with self.subTest(key=key):
                obj = source()
                obj[key] = value
                with self.assertRaisesRegex(TokenBudgetError, "quarantined"):
                    audit_prompts(obj, lambda _: [2])

    def test_render_contract_passed_to_tokenizer(self):
        rendered = []
        audit_prompts(source(), lambda text: rendered.append(text) or [12])
        self.assertEqual(len(rendered), 1)
        self.assertTrue(rendered[0].startswith("### Task:\n"))
        self.assertTrue(rendered[0].endswith("\n\n### Answer:\n"))


if __name__ == "__main__":
    unittest.main()
