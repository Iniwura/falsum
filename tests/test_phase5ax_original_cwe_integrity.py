import unittest
from falsum.phase5ax_original_cwe_integrity import PAIR, classify, norm


class CWEIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.names = {"252": "Unchecked Return Value", "829": "Inclusion of Functionality from Untrusted Control Sphere"}
        self.aliases = {norm(v): {k} for k, v in self.names.items()}
        self.ids = set(self.names) | {"1194"}

    def check(self, key, title):
        return classify(key, title, self.names, self.aliases, self.ids)

    def test_exact_misattribution(self):
        self.assertEqual(self.check("829", "Unchecked Return Value"), "OTHER_WEAKNESS_TITLE")
        self.assertEqual(self.check("252", "Unchecked Return Value"), "CANONICAL_TITLE_MATCH")

    def test_noncanonical_paraphrase_abstains(self):
        self.assertEqual(self.check("252", "unchecked results from calls"), "UNRESOLVED_TITLE")

    def test_unknown_and_category(self):
        self.assertEqual(self.check("999999", "Unchecked Return Value"), "UNKNOWN_ID")
        self.assertEqual(self.check("1194", "Unchecked Return Value"), "OTHER_WEAKNESS_TITLE")

    def test_ambiguous_title_abstains(self):
        self.aliases[norm("duplicate title")] = {"252", "829"}
        self.assertEqual(self.check("1194", "duplicate title"), "UNRESOLVED_TITLE")

    def test_strict_explicit_pair_extraction(self):
        self.assertEqual(PAIR.findall("A (CWE-829 Unchecked Return Value). B (CWE‑252: Unchecked Return Value)."),
                         [("829", "Unchecked Return Value"), ("252", "Unchecked Return Value")])
        self.assertEqual(PAIR.findall("CWE-829 is discussed. (CWE-829) (CWE-252, CWE-829)"), [])


if __name__ == "__main__":
    unittest.main()
