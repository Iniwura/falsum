"""Offline evaluation-harness tests. No pretrained model or real user data."""
import copy
import math
import hashlib
import json
import tempfile
from pathlib import Path
import unittest
from falsum.model_eval import (ModelEvaluationError, ModernBertAdapterScorer,
                               evaluate_counterfactual, render, adapter_artifact_manifest)


def cases():
    result = []
    for split, name in (("train", "x"), ("validation", "y"), ("holdout", "z")):
        for suffix, good, bad in (("on", "Flag the production exposure.", "No production exposure exists."),
                                  ("off", "No production exposure exists.", "Flag the production exposure.")):
            result.append({"id": f"{name}-{suffix}", "split": split, "contrast_set_id": name,
                           "prompt": f"Review system {name}: deployment production={suffix}.",
                           "contrast_chosen": good, "contrast_rejected": bad})
    return result


class TestModelEval(unittest.TestCase):
    def test_exact_renderer(self):
        self.assertEqual(render("Question?", "Answer!"), "### Task:\nQuestion?\n\n### Answer:\nAnswer!")

    def test_no_prompt_scorer_is_chance_by_construction(self):
        report = evaluate_counterfactual(cases(), lambda _prompt, answer: float("Flag" in answer))
        self.assertEqual(report["splits"]["validation"]["pairwise_fraction"], 0.5)
        self.assertEqual(report["splits"]["holdout"]["pairwise_fraction"], 0.5)
        self.assertFalse(report["counterfactual_families"]["y"]["both_contexts_correct"])
        self.assertEqual(report["answer_only_ablation"]["validation"]["pairwise_fraction"], 0.5)

    def test_context_dependent_scorer_reaches_both_contexts(self):
        def scorer(prompt, answer):
            finding = "production=on" in prompt
            return float(("Flag" in answer) == finding)
        report = evaluate_counterfactual(cases(), scorer)
        for split in ("train", "validation", "holdout"):
            self.assertEqual(report["splits"][split]["pairwise_fraction"], 1.0)
        self.assertTrue(all(v["both_contexts_correct"] for v in report["counterfactual_families"].values()))
        self.assertEqual(report["answer_only_ablation"]["holdout"]["pairwise_fraction"], 0.5)

    def test_zero_scorer_ties_count_half_not_wins(self):
        report = evaluate_counterfactual(cases(), lambda *_: 0.0)
        self.assertEqual(report["splits"]["holdout"]["ties"], 2)
        self.assertEqual(report["splits"]["holdout"]["pairwise_fraction"], 0.5)

    def test_non_finite_and_invalid_scores_refused(self):
        for val in (math.nan, math.inf, -math.inf, "1", True, None):
            with self.subTest(val=val):
                with self.assertRaises(ModelEvaluationError):
                    evaluate_counterfactual(cases(), lambda *_: val)

    def test_missing_holdout_refused(self):
        with self.assertRaisesRegex(ModelEvaluationError, "holdout"):
            evaluate_counterfactual([x for x in cases() if x["split"] != "holdout"], lambda *_: 0)

    def test_cross_split_leakage_refused(self):
        data = cases()
        data[-2]["contrast_set_id"] = "y"
        data[-1]["contrast_set_id"] = "y"
        with self.assertRaisesRegex(ModelEvaluationError, "leakage"):
            evaluate_counterfactual(data, lambda *_: 0)

    def test_non_swapped_answers_refused(self):
        data = cases()
        data[1]["contrast_rejected"] = "A completely different answer."
        with self.assertRaisesRegex(ModelEvaluationError, "reversals"):
            evaluate_counterfactual(data, lambda *_: 0)

    def test_duplicate_ids_refused(self):
        data = cases()
        data[1]["id"] = data[0]["id"]
        with self.assertRaisesRegex(ModelEvaluationError, "duplicate"):
            evaluate_counterfactual(data, lambda *_: 0)

    def test_no_model_without_adapter(self):
        with self.assertRaisesRegex(ModelEvaluationError, "LoRA adapter"):
            ModernBertAdapterScorer("/path/that/does/not/exist")

    def test_invalid_case_shapes(self):
        for malformed in ([], [{}], ["wrong"], None):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ModelEvaluationError):
                    evaluate_counterfactual(malformed, lambda *_: 0)

    def test_adapter_manifest_hashes_bytes_and_detects_edits(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "adapter_config.json").write_text('{"peft_type":"LORA"}', encoding="utf-8")
            (root / "adapter_model.safetensors").write_bytes(b"synthetic-not-actual-weights")
            before = adapter_artifact_manifest(root)
            self.assertEqual(len(before["files"]), 2)
            (root / "adapter_model.safetensors").write_bytes(b"modified")
            after = adapter_artifact_manifest(root)
            self.assertNotEqual(before["sha256"], after["sha256"])

    def test_incomplete_adapter_refused(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(ModelEvaluationError, "adapter_config"):
                adapter_artifact_manifest(d)

    def test_adapter_symlink_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "adapter_config.json").write_text("{}")
            (root / "adapter_model.safetensors").write_bytes(b"data")
            (root / "link").symlink_to("adapter_model.safetensors")
            with self.assertRaisesRegex(ModelEvaluationError, "symlinks"):
                adapter_artifact_manifest(root)

    def test_render_refuses_non_string(self):
        with self.assertRaises(ModelEvaluationError):
            render(None, "answer")

if __name__ == '__main__':
    unittest.main()
