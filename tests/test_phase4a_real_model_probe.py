"""Only synthetic parser/guard tests, NOT real model scoring or independent labels."""
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from falsum import phase4a_real_model_probe as m


def source_fixture():
    cases = []
    answers = [
        {"id": "A", "text": "The declared version is within the pinned advisory interval."},
        {"id": "B", "text": "The declared version is outside the pinned advisory interval."},
    ]
    for ident, pkg, ver, ghsa, wanted in m.CASE_PINS:
        cases.append({
            "case_id": ident, "source_package": pkg, "source_release": ver,
            "advisory": ghsa,
            "mechanically_source_derived_preference": wanted,
            "version_in_this_one_advisory_range": wanted == "A",
            "public_catalogue_question_not_independent_expert_label": True,
            "model_score_measured": False, "training_authorized": False,
            "question": "A direct package dependency has the declared release and the pinned GitHub-reviewed advisory. Which single advisory-version interval finding is supported by verified source records?",
            "candidate_answers": answers,
        })
    return {
        "schema_version": 1, "status": m.SOURCE_STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "case_count": 6, "distinct_package_projects": 3,
        "catalogue_version_reversal_pairs": 3,
        "pinned_public_advisory_database_commit": "b2a0c7d47ab94089f8774eacdc65ad80f2457170",
        "catalogue_source_verified_by_exact_git_blobs": True,
        "live_pypi_release_existence_checked": True,
        "not_blind_or_private_holdout": True,
        "not_model_pretraining_disjoint": True,
        "not_independent_expert_reviewed": True,
        "model_scores_measured": False, "independent_expert_labels": 0,
        "new_network_eligible_rows": 0, "registered_evaluator": False,
        "automatic_registration_permitted": False, "trainable_pairs": [],
        "provenance": [{"pinned_advisory_json_sha256": x} for x in m.ADVISORY_DIGESTS],
        "cases": cases,
    }


class Phase4APublicOldModelProbeTests(unittest.TestCase):
    """Explicit test fixtures; synthetic scores cannot be mistaken for authentic."""
    def setUp(self):
        self.source = source_fixture()
        self.raw = json.dumps(self.source, sort_keys=True).encode()
        self.tokenizer = b"fixture-tokenizer-not-real"
        self.patches = (
            patch.object(m, "SOURCE_SHA256", m.sha(self.raw)),
            patch.object(m, "TOKENIZER_SHA256", m.sha(self.tokenizer)),
        )
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        self.frozen = m.make_inputs(self.raw, self.tokenizer,
            lambda s: [50281, 1501, 1502, 1503, 1504, 1505, 1506, 50282])

    def test_correct_synthetic_input_contract_is_bounded_and_not_a_holdout(self):
        self.assertEqual(len(self.frozen["inputs"]), 12)
        self.assertEqual(len({r["id"] for r in self.frozen["inputs"]}), 12)
        self.assertEqual([r["source_catalogue_expected"] for r in self.frozen["inputs"][::2]],
                         ["A", "B"]*3)
        self.assertFalse(self.frozen["blind_holdout"])
        self.assertFalse(self.frozen["network_eligible"])
        self.assertFalse(self.frozen["training_allowed"])
        self.assertEqual(self.frozen["independent_expert_labels"], 0)

    def _fake_packets(self, mode):
        # Synthetic fixture: the real CI runs the unchanged official model,
        # and _score verifies its actual manifests and repeat-consistent f32.
        scores = {}
        for row in self.frozen["inputs"]:
            case_ix = next(i for i, c in enumerate(m.CASE_PINS)
                           if c[0] == row["source_case_id"])
            correct = m.CASE_PINS[case_ix][-1]
            if mode == "constant_A":
                winning = "A"
            elif mode == "correct":
                winning = correct
            elif mode == "constant_B":
                winning = "B"
            else:
                raise ValueError(mode)
            scores[row["id"]] = {"value": 2.0 if row["answer_id"] == winning else 1.0}
        return scores

    def _synthetic_audit(self, packets):
        def fake_score(packet, ident):
            return {"float32_value": packet["value"],
                    "float32_score_hex": "0x40000000" if packet["value"] == 2.0
                    else "0x3f800000"}
        with patch.object(m, "_score", fake_score):
            return m.audit(self.raw, self.frozen, packets)

    def test_constant_A_is_three_of_six_and_zero_complete_reversals(self):
        result = self._synthetic_audit(self._fake_packets("constant_A"))
        self.assertEqual(result["catalogue_fact_matches"], 3)
        self.assertEqual(result["complete_version_fact_reversals"], 0)
        self.assertEqual(result["model_preference_reversal_count"], 0)
        self.assertEqual(result["constant_A_baseline_matches"], 3)
        self.assertEqual(result["constant_B_baseline_matches"], 3)
        self.assertTrue(result["model_release_veto_remains"])
        self.assertFalse(result["automatic_registration_permitted"])
        self.assertFalse(result["network_accuracy_certified"])
        self.assertFalse(result["registered_evaluator"])

    def test_synthetic_ideal_behavior_is_not_claimed_as_real(self):
        result = self._synthetic_audit(self._fake_packets("correct"))
        self.assertEqual(result["catalogue_fact_matches"], 6)
        self.assertEqual(result["complete_version_fact_reversals"], 3)
        self.assertEqual(result["model_preference_reversal_count"], 3)
        self.assertEqual(result["genuine_repeated_inference_calls"], 24)
        self.assertEqual(result["independent_expert_labels"], 0)
        self.assertTrue(result["not_blind_or_private_holdout"])
        self.assertTrue(result["model_release_veto_remains"])
        self.assertFalse(result["automatic_registration_permitted"])

    def test_missing_fake_model_packet_fails(self):
        scores = self._fake_packets("constant_A")
        del scores[next(iter(scores))]
        with self.assertRaises(ValueError):
            self._synthetic_audit(scores)

    def test_mutated_source_or_forged_advisory_fails(self):
        broken = json.loads(self.raw)
        broken["cases"][1]["mechanically_source_derived_preference"] = "A"
        with self.assertRaises(ValueError):
            m.load_source(json.dumps(broken).encode())
        with self.assertRaises(ValueError):
            m.load_source(b'{"unexpected":"fixture"}')
        broken = json.loads(self.raw)
        broken["provenance"][0]["pinned_advisory_json_sha256"] = "0"*64
        with patch.object(m, "SOURCE_SHA256", m.sha(json.dumps(broken).encode())):
            with self.assertRaises(ValueError):
                m.load_source(json.dumps(broken).encode())

    def test_malformed_frozen_tokens_or_label_claims_fail_closed(self):
        scores = self._fake_packets("constant_B")
        for key, val in (("blind_holdout", True), ("independent_expert_labels", 1),
                         ("training_allowed", True), ("network_eligible", True),
                         ("registered_evaluator", True)):
            with self.subTest(key=key):
                broken = copy.deepcopy(self.frozen)
                broken[key] = val
                with patch.object(m, "_score", lambda packet, ident: {
                    "float32_value": packet["value"], "float32_score_hex": "0x40000000"
                }), self.assertRaises(ValueError):
                    m.audit(self.raw, broken, scores)
        bad = copy.deepcopy(self.frozen)
        bad["inputs"][0]["question_sha256"] = "f"*64
        with self.assertRaises(ValueError):
            self._synthetic_audit_from(bad, scores)

    def _synthetic_audit_from(self, frozen, scores):
        with patch.object(m, "_score", lambda p, ident: {
            "float32_value": p["value"], "float32_score_hex": "0x40000000"
        }):
            return m.audit(self.raw, frozen, scores)

    def test_tokenizer_hash_and_truncation_fail_closed(self):
        with self.assertRaises(ValueError):
            m.make_inputs(self.raw, b"wrong-tokenizer",
                          lambda s: [50281, 100, 50282])
        with self.assertRaises(ValueError):
            m.make_inputs(self.raw, self.tokenizer,
                          lambda s: [50281] + [7]*256 + [50282])
        with self.assertRaises(ValueError):
            m.make_inputs(self.raw, self.tokenizer,
                          lambda s: [50281, 300, 50282])
        self.assertEqual(m.score_id("docling-core-2.48.3", "A"),
                         "docling-core-2-48-3--A")


if __name__ == "__main__":
    unittest.main()
