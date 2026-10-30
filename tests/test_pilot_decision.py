"""Research-only audit: fixtures are deliberately fictional; no model is loaded."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.model_eval import evaluate_counterfactual
from falsum.pilot_decision import PilotDecisionError, analyze, main


def samples():
    rows = []
    for split, family in (("train", "training"), ("validation", "validation"), ("holdout", "holdout")):
        for condition, good, bad in (
                ("on", "Flag deployed vulnerability.", "No deployed vulnerability."),
                ("off", "No deployed vulnerability.", "Flag deployed vulnerability.")):
            rows.append({"id": family + "-" + condition, "split": split,
                         "contrast_set_id": family, "prompt": "production=" + condition,
                         "contrast_chosen": good, "contrast_rejected": bad})
    return rows


def inputs(context_sensitive=False):
    scorer = ((lambda prompt, answer: float(("Flag" in answer) == ("production=on" in prompt)))
              if context_sensitive else (lambda prompt, answer: float("Flag" in answer)))
    report = evaluate_counterfactual(samples(), scorer)
    report.update({
        "model_artifact_integrity_verified": True,
        "model_training_provenance_verified": False,
        "benchmark_sha256": "a" * 64,
        "casebook_sha256": "b" * 64,
        "adapter_artifact": {"sha256": "c" * 64,
                             "integrity": "SHA256_OF_LOCAL_FILES_ONLY"},
    })
    official = {"intent": "SECURITY_REVIEW_GENERAL", "base_model": "answerdotai/ModernBERT-base",
                "train_pairs": 52, "n_eval": 6, "gate_split": "test",
                "pairwise_accuracy": 0.8333, "verdict": "PASS"}
    pilot = {"intent": "SECURITY_REVIEW_GENERAL", "research_only": True,
             "network_eligible": False, "training_authorized_for_submission": False,
             "human_reviews": 0,
             "partitions": {k: {"cases": n, "sha256": c * 64}
                            for k, n, c in (("train", 52, "d"), ("validation", 6, "e"), ("holdout", 6, "f"))}}
    return official, report, pilot


class PilotDecisionTests(unittest.TestCase):
    def test_actual_style_report_detects_context_blind_model(self):
        result = analyze(*inputs())
        self.assertEqual(result["status"], "BLOCKED_RESEARCH_ONLY")
        self.assertFalse(result["network_eligible"])
        self.assertFalse(result["registration_authorized"])
        self.assertEqual(result["official_training"]["pairwise_accuracy"], 0.8333)
        self.assertEqual(result["research_counterfactual"]["families_correct_in_both_contexts"], 0)
        self.assertEqual(result["research_counterfactual"]["validation_pairwise_accuracy"], 0.5)

    def test_even_full_context_performance_cannot_authorize_registration(self):
        result = analyze(*inputs(context_sensitive=True))
        self.assertEqual(result["research_counterfactual"]["families_correct_in_both_contexts"], 3)
        self.assertEqual(result["research_counterfactual"]["holdout_pairwise_accuracy"], 1)
        self.assertEqual(result["status"], "BLOCKED_RESEARCH_ONLY")
        self.assertFalse(result["registration_authorized"])

    def test_tampered_individual_margin_fails(self):
        a, b, c = inputs()
        b["case_scores"][0]["margin"] = 500
        with self.assertRaisesRegex(PilotDecisionError, "margin contradicts"):
            analyze(a, b, c)

    def test_tampered_aggregate_fails(self):
        a, b, c = inputs()
        b["splits"]["validation"]["wins"] = 2
        with self.assertRaisesRegex(PilotDecisionError, "contradicts"):
            analyze(a, b, c)

    def test_tampered_family_pass_fails(self):
        a, b, c = inputs()
        b["counterfactual_families"]["validation"]["both_contexts_correct"] = True
        with self.assertRaisesRegex(PilotDecisionError, "family report contradicts"):
            analyze(a, b, c)

    def test_nonfinite_score_fails(self):
        a, b, c = inputs()
        b["case_scores"][0]["score_chosen"] = float("nan")
        with self.assertRaisesRegex(PilotDecisionError, "finite"):
            analyze(a, b, c)

    def test_quarantine_cannot_be_lifted_by_modifying_input(self):
        for field, value in (("human_reviews", 1), ("network_eligible", True),
                             ("research_only", False), ("training_authorized_for_submission", True)):
            with self.subTest(field=field):
                a, b, c = inputs()
                c[field] = value
                with self.assertRaisesRegex(PilotDecisionError, "quarantined"):
                    analyze(a, b, c)

    def test_official_test_mismatch_fails(self):
        a, b, c = inputs()
        a["n_eval"] = 100
        with self.assertRaisesRegex(PilotDecisionError, "holdout"):
            analyze(a, b, c)

    def test_nonofficial_base_model_fails(self):
        a, b, c = inputs()
        a["base_model"] = "some-random-model"
        with self.assertRaisesRegex(PilotDecisionError, "architecture"):
            analyze(a, b, c)

    def test_missing_real_scores_fails(self):
        a, b, c = inputs()
        b["case_scores"] = []
        with self.assertRaisesRegex(PilotDecisionError, "case-level"):
            analyze(a, b, c)

    def test_unverified_adapter_fails(self):
        a, b, c = inputs()
        b["model_artifact_integrity_verified"] = False
        with self.assertRaisesRegex(PilotDecisionError, "provenance"):
            analyze(a, b, c)

    def test_cli_writes_report_once_and_refuses_overwrite(self):
        a, b, c = inputs()
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for name, doc in (("official", a), ("counterfactual", b), ("pilot", c)):
                (root / (name + ".json")).write_text(json.dumps(doc), encoding="utf-8")
            cmd = ["--official", str(root/"official.json"),
                   "--counterfactual", str(root/"counterfactual.json"),
                   "--pilot", str(root/"pilot.json"),
                   "--output", str(root/"decision.json")]
            self.assertEqual(main(cmd), 0)
            result = json.loads((root/"decision.json").read_text(encoding="utf-8"))
            self.assertFalse(result["registration_authorized"])
            with self.assertRaises(SystemExit):
                main(cmd)


if __name__ == "__main__":
    unittest.main()
