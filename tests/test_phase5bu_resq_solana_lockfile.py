import unittest
from unittest.mock import patch

from falsum import phase5bu_resq_solana_lockfile as m


class ResQSolanaLockfileTests(unittest.TestCase):
    def test_protocol_freezes_real_app_and_advisory_roster(self):
        protocol = m._load_protocol()
        self.assertEqual(protocol["application"]["repository"], "resq-software/programs")
        self.assertEqual(protocol["application"]["commit"], "76ac2d3765b7d5defa403c1b141e898782b4c923")
        self.assertEqual(protocol["application"]["resolved_version"], "1.0.0-rc.4")
        self.assertEqual(
            [row["id"] for row in protocol["advisory_database"]["advisories"]],
            ["RUSTSEC-2026-0144", "RUSTSEC-2026-0146"],
        )

    def test_rustsec_frontmatter_extracts_stable_and_prerelease_bounds(self):
        stable = b'''\x60\x60\x60toml
[advisory]
id = "RUSTSEC-2026-0144"
package = "anchor-lang"
[versions]
patched = [">= 1.0.2"]
unaffected = ["< 1.0.0"]
\x60\x60\x60
'''
        prerelease = b'''\x60\x60\x60toml
[advisory]
id = "RUSTSEC-2026-0146"
package = "anchor-lang"
[versions]
patched = [">= 1.0.0-rc.2"]
unaffected = ["< 1.0.0-rc.1"]
\x60\x60\x60
'''
        self.assertEqual(m._rustsec_interval(stable, "RUSTSEC-2026-0144", "anchor-lang"),
                         ("1.0.0", "1.0.2"))
        self.assertEqual(m._rustsec_interval(prerelease, "RUSTSEC-2026-0146", "anchor-lang"),
                         ("1.0.0-rc.1", "1.0.0-rc.2"))

    def test_real_resq_prerelease_is_outside_both_affected_ranges(self):
        cases = [
            ("1.0.0-rc.4", "1.0.0", "1.0.2", m.INAPPLICABLE),
            ("1.0.0-rc.4", "1.0.0-rc.1", "1.0.0-rc.2", m.INAPPLICABLE),
            ("1.0.0-rc.1", "1.0.0-rc.1", "1.0.0-rc.2", m.APPLICABLE),
            ("1.0.0-rc.2", "1.0.0-rc.1", "1.0.0-rc.2", m.INAPPLICABLE),
            ("1.0.0", "1.0.0", "1.0.2", m.APPLICABLE),
            ("1.0.2", "1.0.0", "1.0.2", m.INAPPLICABLE),
        ]
        for version, introduced, fixed, expected in cases:
            with self.subTest(version=version, introduced=introduced, fixed=fixed):
                self.assertEqual(m._candidate_status(version, introduced, fixed), expected)
                self.assertEqual(m._node_reference_status(version, introduced, fixed), expected)

    def test_large_lockfile_fetch_is_bounded_and_git_blob_verified(self):
        raw = b"version = 4\\n"
        spec = {
            "key": "resolved_lockfile",
            "repo": "resq-software/programs",
            "commit": "76ac2d3765b7d5defa403c1b141e898782b4c923",
            "path": "Cargo.lock",
            "blob": m.git_blob(raw),
        }

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                return raw[:limit]

        with patch.object(m, "urlopen", return_value=Response()):
            self.assertEqual(m._fetch_app_source(spec), raw)

        bad = dict(spec, blob="0" * 40)
        with patch.object(m, "urlopen", return_value=Response()):
            with self.assertRaises(Exception):
                m._fetch_app_source(bad)

    def test_cargo_lock_requires_one_registry_resolved_package(self):
        raw = b'''version = 4

[[package]]
name = "anchor-lang"
version = "1.0.0-rc.4"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
'''
        self.assertEqual(m._cargo_lock_package(raw, "anchor-lang")["version"], "1.0.0-rc.4")
        duplicate = raw + b'''
[[package]]
name = "anchor-lang"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
'''
        with self.assertRaises(Exception):
            m._cargo_lock_package(duplicate, "anchor-lang")

    def test_candidate_fails_closed_on_unsupported_version(self):
        self.assertEqual(m._candidate_status("1.0", "1.0.0", "1.0.2"), m.UNKNOWN)
        self.assertEqual(m._candidate_status("not-a-version", "1.0.0", "1.0.2"), m.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
