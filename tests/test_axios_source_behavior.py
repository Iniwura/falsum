"""Fail-closed offline Axios source materialization guards."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from falsum.axios_source_behavior import (
    AxiosEvidenceError, FIX, PARENT, PROJECT, materialize,
)
from falsum.real_fix_replay import git_blob_sha, raw_url


class SourceBehaviorTests(unittest.TestCase):
    def fixture(self):
        a,b=b"'use strict';\nmodule.exports = 1;\n",b"'use strict';\nmodule.exports = 2;\n"
        mapping={"lib/core/buildFullPath.js":(git_blob_sha(a),git_blob_sha(b))}
        sources={
            raw_url(PROJECT,PARENT,"lib/core/buildFullPath.js"):a,
            raw_url(PROJECT,FIX,"lib/core/buildFullPath.js"):b,
        }
        return mapping,sources

    def test_pinned_original_and_fixed_materialization_is_not_label(self):
        blobs,inputs=self.fixture()
        with tempfile.TemporaryDirectory() as d, patch(
                "falsum.axios_source_behavior.FILES",blobs):
            out=Path(d)/"source"
            report=materialize(out,lambda url:inputs[url])
            self.assertEqual(report["status"],"PINNED_PUBLIC_AXIOS_SOURCE_FOR_LOCAL_BEHAVIOR_AUDIT")
            self.assertFalse(report["network_eligible"])
            self.assertFalse(report["has_human_security_review"])
            self.assertEqual((out/"parent/lib/core/buildFullPath.js").read_bytes(),
                             inputs[raw_url(PROJECT,PARENT,"lib/core/buildFullPath.js")])
            with self.assertRaisesRegex(AxiosEvidenceError,"overwrite"):
                materialize(out,lambda url:inputs[url])

    def test_forged_git_blob_rejected_without_output(self):
        blobs,inputs=self.fixture()
        inputs[raw_url(PROJECT,PARENT,"lib/core/buildFullPath.js")]=b"tampered\n"
        with tempfile.TemporaryDirectory() as d, patch(
                "falsum.axios_source_behavior.FILES",blobs):
            out=Path(d)/"source"
            with self.assertRaisesRegex(AxiosEvidenceError,"SHA mismatch"):
                materialize(out,lambda url:inputs[url])
            self.assertFalse(out.exists())

    def test_missing_file_refuses_to_create_false_complete_manifest(self):
        blobs,inputs=self.fixture()
        inputs.pop(raw_url(PROJECT,FIX,"lib/core/buildFullPath.js"))
        with tempfile.TemporaryDirectory() as d, patch(
                "falsum.axios_source_behavior.FILES",blobs):
            out=Path(d)/"source"
            with self.assertRaises(KeyError):
                materialize(out,lambda url:inputs[url])
            self.assertFalse((out/"MANIFEST.json").exists())


if __name__=="__main__":
    unittest.main()
