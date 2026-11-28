import os
import unittest
from pathlib import Path

from falsum import phase5by_resq_rustsec_advisory_expansion as m


class Phase5BYRealSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.protocol = m._load_protocol()
        raw_dir = os.environ.get("FALSUM_PHASE5BY_DB_DIR")
        if not raw_dir:
            raise RuntimeError("FALSUM_PHASE5BY_DB_DIR is required for real-source tests")
        cls.db_dir = Path(raw_dir)
        cls.verified = m._verify_database(cls.db_dir, cls.protocol)

    def test_four_new_cargo_audit_findings_are_source_bound_and_applicable(self):
        expected = {
            "RUSTSEC-2026-0387": ("crypto-bigint", "0.5.5"),
            "RUSTSEC-2024-0344": ("curve25519-dalek", "3.2.0"),
            "RUSTSEC-2022-0093": ("ed25519-dalek", "1.0.1"),
            "RUSTSEC-2026-0592": ("url", "2.5.8"),
        }
        rows = self.protocol["advisory_database"]["new_advisories"]
        self.assertEqual({row["id"] for row in rows}, set(expected))
        for row in rows:
            with self.subTest(advisory=row["id"]):
                self.assertEqual((row["package"], row["version"]), expected[row["id"]])
                raw = (self.db_dir / row["path"]).read_bytes()
                self.assertEqual(m.git_blob(raw), row["blob"])
                metadata = m._frontmatter(raw, row["id"], row["package"])
                self.assertEqual(
                    m._candidate_status(row["version"], metadata["versions"]),
                    m.APPLICABLE,
                )

    def test_two_prior_anchor_controls_remain_inapplicable(self):
        expected = {
            "RUSTSEC-2026-0144": "INAPPLICABLE",
            "RUSTSEC-2026-0146": "INAPPLICABLE",
        }
        for row in self.protocol["advisory_database"]["calibration_advisories"]:
            with self.subTest(advisory=row["id"]):
                raw = (self.db_dir / row["path"]).read_bytes()
                self.assertEqual(m.git_blob(raw), row["blob"])
                metadata = m._frontmatter(raw, row["id"], row["package"])
                self.assertEqual(
                    m._candidate_status(row["version"], metadata["versions"]),
                    expected[row["id"]],
                )


if __name__ == "__main__":
    unittest.main()
