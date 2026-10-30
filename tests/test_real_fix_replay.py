"""No internet: test exact upstream byte replay, refusal on any drift."""
import copy
import hashlib
import json
import unittest
from pathlib import Path

from falsum.real_fix_corpus import load_queue
from falsum.real_fix_replay import (
    ReplayError, apply_patch, git_blob_sha, raw_url, replay_case, verify_report,
)

ROOT = Path(__file__).resolve().parents[1]

BEFORE = b"lineA\nunsafe\nlineC\n"
AFTER = b"lineA\nsafe\nlineC\n"
PATCH = "@@ -1,3 +1,3 @@\n lineA\n-unsafe\n+safe\n lineC"
TEST_BEFORE = b"header\nfooter\n"
TEST_AFTER = b"header\ntest added\nfooter\n"
TEST_PATCH = "@@ -1,2 +1,3 @@\n header\n+test added\n footer"


def setup():
    queue = load_queue(ROOT / "data/real-fix-queue.json")
    content = {}
    cases = []
    for item in queue["cases"]:
        files = {}
        for key, path, pre, post, patch in (
                ("source", item["source_path"], BEFORE, AFTER, PATCH),
                ("regression_test", item["test_path"], TEST_BEFORE, TEST_AFTER, TEST_PATCH)):
            files[key] = {"file_path": path, "post_fix_blob": git_blob_sha(post),
                          "sha256": hashlib.sha256(patch.encode()).hexdigest(), "patch": patch}
            content[raw_url(item["repository"], item["parent"], path)] = pre
            content[raw_url(item["repository"], item["commit"], path)] = post
        cases.append({"id": item["id"], "repository": item["repository"], "commit": item["commit"],
                      "parent": item["parent"], "external_review_status": "NOT_REVIEWED",
                      "network_eligible": False, "training_authorized": False, **files})
    sha = hashlib.sha256(json.dumps(cases, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    report = {"status": "SOURCE_VERIFIED_LABELS_UNREVIEWED", "cases_sha256": sha,
              "independent_human_reviews": 0, "network_eligible": False,
              "training_authorized": False, "cases": cases}
    return report, content


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.report, self.content = setup()

    def reader(self, url):
        return self.content[url]

    def test_all_six_files_reconstruct_exactly(self):
        result = verify_report(self.report, self.reader)
        self.assertEqual(result["cases_replayed"], 4)
        self.assertEqual(result["file_replays_verified"], 8)
        self.assertFalse(result["network_eligible"])
        self.assertFalse(result["training_authorized"])
        self.assertEqual(result["independent_human_reviews"], 0)
        self.assertTrue(all(
            f["exact_patch_replay_verified"] for r in result["verified"] for f in r["files"].values()))

    def test_multi_hunk_exact_application(self):
        before = b"top\nold\nmid\nold2\nend\n"
        patch = "@@ -1,3 +1,3 @@\n top\n-old\n+new\n mid\n@@ -4,2 +4,2 @@\n-old2\n+new2\n end"
        self.assertEqual(apply_patch(before, patch), b"top\nnew\nmid\nnew2\nend\n")

    def test_changed_parent_bytes_rejected(self):
        key = raw_url(self.report["cases"][0]["repository"],
                      self.report["cases"][0]["parent"],
                      self.report["cases"][0]["source"]["file_path"])
        self.content[key] = b"lineA\nnot the old line\nlineC\n"
        with self.assertRaisesRegex(ReplayError, "context or removed"):
            verify_report(self.report, self.reader)

    def test_wrong_upstream_post_bytes_rejected(self):
        item = self.report["cases"][0]
        key = raw_url(item["repository"], item["commit"], item["source"]["file_path"])
        self.content[key] = b"lineA\nmalicious different new version\nlineC\n"
        with self.assertRaisesRegex(ReplayError, "Git blob SHA"):
            verify_report(self.report, self.reader)

    def test_tampered_patch_digest_rejected(self):
        item = self.report["cases"][0]
        item["source"]["patch"] = "@@ -1,3 +1,3 @@\n lineA\n-unsafe\n+danger\n lineC"
        with self.assertRaisesRegex(ReplayError, "digest"):
            verify_report(self.report, self.reader)

    def test_tampered_patch_with_forged_outer_digest_rejected(self):
        item = self.report["cases"][0]
        item["source"]["patch"] = "@@ -1,3 +1,3 @@\n lineA\n-unsafe\n+danger\n lineC"
        item["source"]["sha256"] = hashlib.sha256(item["source"]["patch"].encode()).hexdigest()
        self.report["cases_sha256"] = hashlib.sha256(json.dumps(
            self.report["cases"], sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        with self.assertRaisesRegex(ReplayError, "reconstruct"):
            verify_report(self.report, self.reader)

    def test_incomplete_unified_hunk_rejected(self):
        with self.assertRaisesRegex(ReplayError, "counts"):
            apply_patch(BEFORE, "@@ -1,3 +1,5 @@\n lineA\n-unsafe\n+safe\n lineC")

    def test_path_escape_rejected(self):
        with self.assertRaisesRegex(ReplayError, "untrusted"):
            raw_url("pallets/jinja", "a"*40, "../config.ini")

    def test_unreviewed_status_is_immutable(self):
        item = self.report["cases"][0]
        item["network_eligible"] = True
        with self.assertRaisesRegex(ReplayError, "promoted"):
            replay_case(item, self.reader)

    def test_report_digest_catches_row_edits(self):
        self.report["cases"][0]["family"] = "wrong"
        with self.assertRaisesRegex(ReplayError, "digest"):
            verify_report(self.report, self.reader)


if __name__ == "__main__":
    unittest.main()
