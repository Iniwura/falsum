import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum import phase5bw_adversarialeval_ingestion as m


class AnjomanMaterialCompatibilityTests(unittest.TestCase):
    @staticmethod
    def row(prompt="Review this dependency and configuration for security findings.",
            source_kind="ai_assisted", source_url="https://example.org/security-review"):
        return {
            "prompt": prompt,
            "chosen": "Insecure, one bounded issue with a source-backed explanation.",
            "rejected": "Secure, no issues; the current evidence is sufficient.",
            "label_kind": "preference_pair",
            "provenance": {"source_kind": source_kind, "source_url": source_url},
        }

    @staticmethod
    def raw(rows):
        return b"".join(
            (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            for row in rows
        )

    def audit(self, rows, intent="SECURITY_REVIEW_GENERAL", authors=None):
        return m._audit_telegraph_material(
            rows, self.raw(rows), intent, authors or {"reviewer:a": 1, "reviewer:b": 1}
        )

    def test_documented_preference_pair_shape_passes_without_submission_claim(self):
        report = self.audit([self.row()])
        self.assertTrue(report["structural_compatibility_verified"])
        self.assertEqual(report["structurally_compatible_rows"], 1)
        self.assertEqual(report["intent"]["family"], "SECURITY_REVIEW")
        self.assertEqual(report["intent"]["kind"], "judgment")
        self.assertEqual(report["pool_activation"]["minimum_distinct_contributors"], 5)
        self.assertFalse(report["submission"]["upload_attempted"])
        self.assertFalse(report["submission"]["signature_created"])
        self.assertFalse(report["submission"]["eligible_claimed"])
        self.assertEqual(
            report["provenance"]["node_provenance_classification"],
            "NOT_OBSERVED_NO_UPLOAD",
        )

    def test_ai_assisted_source_kind_is_preserved_not_promoted(self):
        report = self.audit([self.row(source_kind="ai_assisted")])
        self.assertEqual(report["provenance"]["source_kind_counts"], {"ai_assisted": 1})
        self.assertEqual(
            report["provenance"]["node_provenance_classification"],
            "NOT_OBSERVED_NO_UPLOAD",
        )

    def test_wrong_intent_is_rejected(self):
        row = self.row()
        row["intent_id"] = "CODE_REVIEW_GENERAL"
        with self.assertRaises(m.AuditError):
            self.audit([row])

    def test_duplicate_prompt_after_official_normalization_is_rejected(self):
        rows = [
            self.row(prompt="Review this dependency and configuration for security findings."),
            self.row(prompt="Review this dependency and  configuration for security findings."),
        ]
        with self.assertRaises(m.AuditError):
            self.audit(rows)

    def test_prompt_length_below_documented_minimum_is_rejected(self):
        with self.assertRaises(m.AuditError):
            self.audit([self.row(prompt="Too short")])

    def test_raw_jsonl_row_over_64_kib_is_rejected(self):
        row = self.row(source_url="https://" + "a" * (65 * 1024))
        with self.assertRaises(m.AuditError):
            self.audit([row])


class AdversarialEvalIngestionTests(unittest.TestCase):
    def test_protocol_pins_external_commit_and_sample_before_candidate(self):
        lock = m._load_protocol()
        self.assertEqual(lock["external"]["repository"], "Ritapossible/AdversarialEval")
        self.assertEqual(lock["external"]["commit"],
                         "09f9fa4a584b513720b215731baf54187039ac10")
        self.assertEqual(lock["external"]["expected"]["pairs"], 40)
        self.assertEqual(lock["external"]["expected"]["reviewers"],
                         {"reviewer:fexx": 20, "reviewer:lino": 20})
        self.assertFalse(lock["selection_policy"]["heldout_eligible"])

    def test_row_identity_matches_upstream_nfc_and_whitespace_rule(self):
        self.assertEqual(
            m._row_id("  A\nB  ", "Cafe\u0301", "D"),
            "72fbd6511b708900620dac2f19784f29045656abeb96c487380b294515699c05",
        )

    def test_identifier_extractor_uses_advisory_id_grammar(self):
        self.assertEqual(
            m._identifiers("CVE-2020-8203 GHSA-P6MC-M468-83GW GHSA-AAAA-BBBB-CCCC"),
            {"CVE-2020-8203", "GHSA-P6MC-M468-83GW"},
        )

    def test_overlap_classifier_never_promotes_unknown_rows(self):
        public = {"CVE-2025-27152", "GHSA-JR5F-V2JV-69X6"}
        self.assertEqual(
            m._classify_pair({"GHSA-JR5F-V2JV-69X6"}, public),
            ("PUBLIC_SOURCE_OVERLAP", ["GHSA-JR5F-V2JV-69X6"]),
        )
        self.assertEqual(
            m._classify_pair({"GHSA-F23M-R3PF-42RH"}, public),
            ("PUBLIC_SOURCE_DISJOINT_CANDIDATE", []),
        )
        self.assertEqual(m._classify_pair(set(), public),
                         ("UNCLASSIFIED_NO_ADVISORY_ID", []))

    def test_wilson_interval_matches_published_31_of_40(self):
        low, high = m._wilson(31, 40)
        self.assertEqual([round(100 * low, 1), round(100 * high, 1)], [62.5, 87.7])

    def test_jsonl_rejects_duplicate_keys_and_blank_rows(self):
        with self.assertRaises(m.AuditError):
            m._jsonl(b'{"prompt":"a","prompt":"b"}\n', "fixture")
        with self.assertRaises(m.AuditError):
            m._jsonl(b'{"prompt":"a"}\n\n', "fixture")

    def test_fetch_enforces_frozen_size_limit(self):
        with patch.object(m, "source_bytes", return_value=b"12345"):
            self.assertEqual(m._fetch({"key": "fixture", "max_bytes": 5}), b"12345")
        with patch.object(m, "source_bytes", return_value=b"123456"):
            with self.assertRaises(m.AuditError):
                m._fetch({"key": "fixture", "max_bytes": 5})

    def test_protocol_blob_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / m.PROTOCOL_PATH
            target.parent.mkdir(parents=True)
            target.write_bytes((m.ROOT / m.PROTOCOL_PATH).read_bytes() + b" ")
            with self.assertRaises(m.AuditError):
                m._load_protocol(root)


if __name__ == "__main__":
    unittest.main()
