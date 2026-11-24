import unittest
from falsum import phase5aq_swc_citations as p


class CitationTests(unittest.TestCase):
    def test_registry_relationship_scoped_to_section(self):
        raw = b"## Relationships\n- [CWE-682: Incorrect Calculation](https://cwe.mitre.org/data/definitions/682.html)\n## Description\n[CWE-190: Another](https://cwe.mitre.org/data/definitions/190.html)\n"
        self.assertEqual(p.relationship(raw),682)

    def test_invalid_registry_relationship(self):
        for raw in (b"## Description\nCWE-682", b"## Relationships\n[CWE-682: X](https://cwe.mitre.org/data/definitions/190.html)\n## Description\n",
                    b"## Relationships\n[CWE-682: X](https://cwe.mitre.org/data/definitions/682.html)\n[CWE-190: Y](https://cwe.mitre.org/data/definitions/190.html)\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                p.relationship(raw)

    def test_exact_citation_in_structured_or_summary(self):
        self.assertEqual(p.citation_check(682,{"issues":["CWE-682: Calculation"],"summary":""})["state"],"EXACT_CITATION_PRESENT")
        self.assertEqual(p.citation_check(682,{"issues":None,"summary":"CWE‑682"})["state"],"EXACT_CITATION_PRESENT")

    def test_unmatched_does_not_imply_wrong_semantics(self):
        r=p.citation_check(682,{"issues":["CWE-190"],"summary":"integer overflow"})
        self.assertEqual(r["state"],"EXACT_CITATION_NOT_OBSERVED")
        self.assertEqual(r["issues"],[190])
        self.assertEqual(p.citation_check(682,{"issues":["CWE-6820"],"summary":""})["state"],"EXACT_CITATION_NOT_OBSERVED")

    def test_missing_not_mismatch(self):
        self.assertEqual(p.citation_check(682,None)["state"],"NO_RECORDED_ANSWER")
        with self.assertRaises(ValueError):
            p.citation_check(682,{"issues":"CWE-682"})

if __name__ == "__main__":
    unittest.main()
