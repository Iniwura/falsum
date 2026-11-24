import unittest
from falsum import phase5au_solana_anchor_evidence as p


class SolanaAnchorTests(unittest.TestCase):
    def test_frozen_version_cases(self):
        rows = p.protocol()["cases"]
        bounds = ((1, 0, 0), (1, 0, 2))
        self.assertEqual(len(rows), 12)
        self.assertEqual(sum(p.classify(r, bounds) == r["expected"] for r in rows), 12)
        self.assertEqual(sum(p.reference_only(r) == r["expected"] for r in rows), 3)
        self.assertEqual(sum(p.reference_only(r) == "APPLICABLE" and
                             r["expected"] != "APPLICABLE" for r in rows), 9)

    def test_version_parser_fails_closed(self):
        for v in (None, 1, [], "1.0", "01.0.1", "1.0.2-rc.1", "1.0.1+meta",
                  " 1.0.1", "1.0.1\n", "1.0.1000000000", "*"):
            with self.subTest(v=v):
                self.assertIsNone(p.exact_version(v))

    def test_immutable_source_lock(self):
        self.assertEqual(len(p.protocol()["sources"]), 3)

    def test_wrong_target_never_applies(self):
        case = dict(ecosystem="crates.io", package="anchor-spl", version="1.0.1",
                    reference=p.ADVISORY)
        self.assertEqual(p.classify(case, ((1, 0, 0), (1, 0, 2))), "UNKNOWN_TARGET")

    def test_substituted_source_rejected(self):
        with self.assertRaises(ValueError):
            p.audit(fetch=lambda _: b"substituted source")

    def test_claimed_affected_range_cannot_override_reviewed_range(self):
        record = dict(id=p.ADVISORY, aliases=[p.CVE],
                      database_specific={"github_reviewed": True},
                      affected=[{"package":{"ecosystem":"crates.io","name":"anchor-lang"},
                                 "ranges":[{"type":"ECOSYSTEM","events":[
                                     {"introduced":"1.0.0"},{"fixed":"1.0.3"}]}]}])
        with self.assertRaises(ValueError):
            p.interval(record)


if __name__ == "__main__":
    unittest.main()
