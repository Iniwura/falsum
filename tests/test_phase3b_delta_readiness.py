"""Never treat a 2026-era delta format conversion as security accuracy."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from falsum.model_eval import adapter_artifact_manifest
from falsum.phase3b_delta_readiness import (
    PREVIOUS_MANIFEST, SOURCE_ARTIFACT_ID, SOURCE_RUN_ID,
    DeltaReadinessError, inspect, locate,
)

ROOT=Path(__file__).resolve().parents[1]


class MigrationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.model=self.root/"SECURITY_REVIEW_GENERAL"/"adapter"
        self.model.mkdir(parents=True)
        self.model.joinpath("adapter_config.json").write_text(json.dumps({
            "peft_type":"LORA","bias":"none","r":8,"lora_alpha":16,
            "target_modules":["Wqkv","Wo","Wi"]
        }))
        self.model.joinpath("adapter_model.safetensors").write_bytes(b"pretend fixture only; not an actual model")
        self.manifest=self.root/"PHASE2U-TRAIN-MANIFEST.json"
        self.source={"status":"AI_PROVISIONAL_CONTEXT_TRANSFER_TRAIN_ONLY_NOT_NETWORK",
                     "network_eligible":False,"training_authorized_for_submission":False,
                     "research_only":True,"independent_human_reviews":0,
                     "training_projects":["test-only"]}
        self.manifest.write_text(json.dumps(self.source))

    def probe(self):
        sha=adapter_artifact_manifest(self.model)["sha256"]
        return inspect(self.root,expected_sha=sha)

    def test_immutable_real_previous_artifact_identity(self):
        self.assertEqual(len(PREVIOUS_MANIFEST),64)
        self.assertEqual(SOURCE_RUN_ID,41283929744)
        self.assertEqual(SOURCE_ARTIFACT_ID,13074383795)

    def test_correct_basic_checkpoint_shape_still_not_certified(self):
        r=self.probe()
        self.assertTrue(r["research_only"])
        self.assertFalse(r["held_out_cross_project_context_transfer_demonstrated"])
        self.assertFalse(r["network_eligible"])
        self.assertFalse(r["registered_evaluator"])
        self.assertEqual(r["original_training_source"],"PHASE2U-AI-PROVISIONAL")
        self.assertEqual(r["rank"],8)

    def test_identity_failure_if_adapter_bytes_change(self):
        sha=adapter_artifact_manifest(self.model)["sha256"]
        self.model.joinpath("adapter_model.safetensors").write_bytes(b"tampered")
        with self.assertRaisesRegex(DeltaReadinessError,"no longer matches"):
            inspect(self.root,expected_sha=sha)

    def test_training_provenance_cannot_be_promoted(self):
        for key,bad in (("network_eligible",True),
                        ("training_authorized_for_submission",True),
                        ("research_only",False),
                        ("independent_human_reviews",1),
                        ("status","READY_FOR_SUBMISSION")):
            with self.subTest(key=key):
                src=copy.deepcopy(self.source);src[key]=bad
                self.manifest.write_text(json.dumps(src))
                with self.assertRaises(DeltaReadinessError):
                    self.probe()

    def test_duplicate_checkpoint_or_missing_manifest_refused(self):
        other=self.root/"second"
        other.mkdir()
        other.joinpath("adapter_config.json").write_text("{}")
        with self.assertRaisesRegex(DeltaReadinessError,"exactly one"):
            locate(self.root)
        other.joinpath("adapter_config.json").unlink()
        self.manifest.unlink()
        with self.assertRaisesRegex(DeltaReadinessError,"source-labeled"):
            locate(self.root)

    def test_no_symlink_checkpoint_hiding(self):
        (self.root/"bad-link").symlink_to(self.model,target_is_directory=True)
        with self.assertRaisesRegex(DeltaReadinessError,"symlink"):
            locate(self.root)

    def test_unsupported_model_type_or_rank_rejected(self):
        for patch in ({"peft_type":"PREFIX_TUNING"},
                      {"r":17},{"r":True},{"target_modules":["down_proj"]},
                      {"use_dora":True}):
            with self.subTest(patch=patch):
                cfg=json.loads((self.model/"adapter_config.json").read_text())
                cfg.update(patch)
                self.model.joinpath("adapter_config.json").write_text(json.dumps(cfg))
                with self.assertRaises(DeltaReadinessError):
                    self.probe()
                self.model.joinpath("adapter_config.json").write_text(json.dumps({
                    "peft_type":"LORA","bias":"none","r":8,"lora_alpha":16,
                    "target_modules":["Wqkv","Wo","Wi"]
                }))


if __name__=="__main__":
    unittest.main()
