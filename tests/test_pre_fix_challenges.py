"""Offline tests for remediation-withheld historical source prompts."""
import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.pre_fix_challenges import (
    ChallengeError, ADVISORY_ID, _canonical, build_challenges, parent_regions, main,
)
from falsum.real_fix_replay import ReplayError, git_blob_sha, raw_url
from test_real_fix_replay import setup


class PreFixChallengeTests(unittest.TestCase):
    def setUp(self):
        self.report, self.files = setup()
        # Offline replay stubs deliberately omit advisory metadata; authentic
        # source reports include these public provenance fields.
        for item in self.report["cases"]:
            item["advisory_url"] = "https://github.com/example/security/advisories/GHSA-0000-0000-0000"
            item["commit_url"] = (
                f'https://github.com/{item["repository"]}/commit/{item["commit"]}')
        self.report["cases_sha256"] = hashlib.sha256(json.dumps(
            self.report["cases"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()

    def reader(self, url):
        return self.files[url]

    def test_all_challenges_use_parent_only_without_labels(self):
        public, audit = build_challenges(self.report, self.reader)
        self.assertEqual(len(public["prompts"]), 4)
        self.assertEqual(len(audit["records"]), 4)
        self.assertFalse(public["network_eligible"])
        self.assertFalse(public["sealed_holdout"])
        self.assertFalse(public["tokenizer_512_verified"])
        self.assertFalse(public["evaluation_authorized"])
        self.assertFalse(public["model_training_authorized"])
        self.assertEqual(public["independent_human_reviews"], 0)
        self.assertEqual(audit["public_prompt_sha256"], hashlib.sha256(_canonical(public)).hexdigest())
        for item in public["prompts"]:
            self.assertEqual(set(item), {"challenge_id", "prompt"})
            self.assertIn("unsafe", item["prompt"])
            self.assertNotIn("new protected code", item["prompt"])
            self.assertNotIn("regression test added", item["prompt"])
            self.assertNotIn("GHSA-", item["prompt"])
            self.assertNotIn("CVE-", item["prompt"])
            self.assertNotIn("github.com", item["prompt"])
            self.assertNotIn("psf/requests", item["prompt"])
            self.assertNotIn("aio-libs/aiohttp", item["prompt"])
            self.assertNotIn("pallets/jinja", item["prompt"])
        self.assertEqual({r["challenge_id"] for r in public["prompts"]},
                         {r["challenge_id"] for r in audit["records"]})
        by_id = {r["challenge_id"]: r for r in audit["records"]}
        for item in public["prompts"]:
            origin = by_id[item["challenge_id"]]["repository"]
            expected_lang = "javascript" if origin == "axios/axios" else "python"
            self.assertIn(chr(96)*3 + expected_lang, item["prompt"])
        self.assertTrue(all(r["human_label"] is None and not r["eligible"] for r in audit["records"]))

    def test_cve_and_ghsa_advisory_leak_matcher(self):
        self.assertIsNotNone(ADVISORY_ID.search("security: GHSA-ab12-cd34-ef56"))
        self.assertIsNotNone(ADVISORY_ID.search("CVE-2025-27152"))
        self.assertIsNone(ADVISORY_ID.search("CVE not present and no vulnerability label"))

    def test_parent_ranges_are_actual_old_source(self):
        old = b"first\nsecond\nthird\nFOURTH\nfifth\nsixth\nseventh\neighth\n"
        patch = "@@ -4,2 +4,2 @@\n-FOURTH\n+other\n fifth"
        regions = parent_regions(old, patch, flank=1)
        self.assertEqual(len(regions), 1)
        self.assertEqual((regions[0]["first_line"], regions[0]["last_line"]), (3, 6))
        self.assertIn("    4 | FOURTH", regions[0]["numbered_source"])
        self.assertNotIn("other", regions[0]["numbered_source"])

    def test_contiguous_hunks_are_deduplicated(self):
        old = b"a\nb\nc\nd\ne\nf\ng\n"
        patch = "@@ -2 +2 @@\n-b\n+B\n@@ -5 +5 @@\n-e\n+E"
        windows = parent_regions(old, patch, flank=2)
        self.assertEqual(len(windows), 1)
        self.assertEqual(windows[0]["first_line"], 1)
        self.assertEqual(windows[0]["last_line"], 7)

    def test_disjoint_hunks_remain_separate(self):
        old = ("\n".join("line" + str(i) for i in range(1, 91)) + "\n").encode()
        patch = "@@ -2 +2 @@\n-line2\n+NEW\n@@ -80 +80 @@\n-line80\n+ALSO_NEW"
        windows = parent_regions(old, patch)
        self.assertEqual(len(windows), 2)

    def test_oversized_hunk_fails_without_truncating(self):
        old = ("\n".join("line" + str(i) for i in range(100)) + "\n").encode()
        patch = "@@ -1,99 +1,99 @@\n"
        with self.assertRaisesRegex(ChallengeError, "line budget"):
            parent_regions(old, patch)

    def test_wrong_parent_material_fails_closed(self):
        item = self.report["cases"][0]
        url = raw_url(item["repository"], item["parent"], item["source"]["file_path"])
        self.files[url] = b"lineA\nfabricated answer\nlineC\n"
        with self.assertRaises(ReplayError):
            build_challenges(self.report, self.reader)

    def test_status_promotion_rejected(self):
        self.report["network_eligible"] = True
        with self.assertRaisesRegex(ReplayError, "unreviewed"):
            build_challenges(self.report, self.reader)

    def test_source_hunk_change_rejected(self):
        self.report["cases"][0]["source"]["patch"] = "@@ -1,3 +1,3 @@\n lineA\n-unsafe\n+wrong fix\n lineC"
        with self.assertRaisesRegex(ReplayError, "digest"):
            build_challenges(self.report, self.reader)

    def test_overwrite_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps(self.report), encoding="utf-8")
            pub = root / "public.json"
            prov = root / "provenance.json"
            args = ["--evidence", str(evidence), "--public-out", str(pub),
                    "--provenance-out", str(prov)]
            with patch("falsum.pre_fix_challenges.build_challenges", side_effect=lambda _: build_challenges(self.report, self.reader)):
                self.assertEqual(main(args), 0)
                self.assertEqual(hashlib.sha256(pub.read_bytes()).hexdigest(),
                                 json.loads(prov.read_text())["public_prompt_sha256"])
                with self.assertRaises(SystemExit):
                    main(args)


if __name__ == "__main__":
    unittest.main()
