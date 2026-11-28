import tempfile
import unittest
from pathlib import Path

from falsum import phase5cc_adversarialeval_source_scope as m


class AdversarialEvalSourceScopeTests(unittest.TestCase):
    def test_protocol_freezes_corrected_roster_before_candidate_inference(self):
        protocol = m.frozen_protocol()
        expected = protocol["expected"]
        self.assertEqual(expected["source_identifier_count"], 10)
        self.assertEqual(len(expected["public_overlap"]), 1)
        self.assertEqual(len(expected["public_source_disjoint_candidates"]), 8)
        self.assertEqual(expected["unclassified_pair_count"], 31)
        self.assertFalse(protocol["selection_policy"]["heldout_eligible"])
        self.assertFalse(protocol["selection_policy"]["candidate_inference_before_freeze"])

    def test_row_23_answer_only_advisory_does_not_create_source_identity(self):
        prompt = (
            "Our Express 4.21.1 app does res.redirect(req.query.returnUrl) "
            "after login with no validation. Severity?"
        )
        source_url = "https://cwe.mitre.org/data/definitions/601.html"
        chosen = (
            "Needs changes, 1 issue: CWE-601 open redirect. "
            "Restrict to relative paths."
        )
        rejected = (
            "Secure, 0 issues. Express 4.21.1 is after "
            "GHSA-rv95-896h-c2vc, so all redirects are safe."
        )
        source_ids = m.source_identifiers(prompt, source_url)
        self.assertEqual(source_ids, set())
        self.assertEqual(
            m.answer_only_identifiers(chosen, rejected, source_ids),
            {"GHSA-RV95-896H-C2VC"},
        )

    def test_row_33_prompt_and_provenance_anchor_the_source_not_answer_alias(self):
        prompt = "We are on express 4.18.2. Affected by GHSA-rv95-896h-c2vc?"
        source_url = "https://github.com/advisories/GHSA-rv95-896h-c2vc"
        chosen = (
            "Needs changes, 1 issue: GHSA-RV95-896H-C2VC / "
            "CVE-2024-29041. Affects <4.19.2."
        )
        rejected = "Secure, 0 issues. That advisory only covers 5.x alpha/beta releases."
        source_ids = m.source_identifiers(prompt, source_url)
        self.assertEqual(source_ids, {"GHSA-RV95-896H-C2VC"})
        self.assertEqual(
            m.answer_only_identifiers(chosen, rejected, source_ids),
            {"CVE-2024-29041"},
        )

    def test_source_identity_does_not_depend_on_candidate_answer_order(self):
        prompt = "Triage GHSA-P6MC-M468-83GW for lodash-es 4.17.19."
        source_url = "https://github.com/advisories/GHSA-p6mc-m468-83gw"
        source_ids = m.source_identifiers(prompt, source_url)
        self.assertEqual(source_ids, {"GHSA-P6MC-M468-83GW"})
        self.assertEqual(
            m.source_identifiers(prompt, source_url),
            m.source_identifiers(prompt, source_url),
        )

    def test_protocol_blob_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / m.PROTOCOL_PATH
            target.parent.mkdir(parents=True)
            target.write_bytes((m.ROOT / m.PROTOCOL_PATH).read_bytes() + b" ")
            with self.assertRaises(m.SourceScopeError):
                m.frozen_protocol(root)


if __name__ == "__main__":
    unittest.main()
