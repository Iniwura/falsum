import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum import phase5bw_adversarialeval_ingestion as m


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
