"""Phase 4X: verify immutable-source external-review guide, not human gold."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

from falsum.phase4p_open_source_review import load_lock
from falsum.source_review_witness_gate import validated_index

ROOT=Path(__file__).resolve().parents[1]
FORM=ROOT/".github/ISSUE_TEMPLATE/independent-executed-source-review.yml"
GUIDE=ROOT/"docs/REVIEW_FOUR_EXECUTED_CASES.md"
LOCK=ROOT/"data/phase4p-three-project-open-review-lock.json"
WITNESS=ROOT/"evidence/phase4u-2026-11-18-permanent-four-executed-source-witness-index.json"
CASE_IDS=("koa-redirect","hono-csrf","langchain-path","langchain-symlink")


def inspect(guide:str,form:str,lock_raw:bytes,witness_raw:bytes)->dict:
    source=load_lock(lock_raw)
    indexed=validated_index(witness_raw,lock_raw)
    if tuple(indexed)!=CASE_IDS:
        raise ValueError("unexpected or mutable four-stage source review selection")
    if not guide.startswith("# Independently review one real upstream security fix"):
        raise ValueError("public reviewer guide missing")
    if not form.startswith("name: Independently review one executed security regression"):
        raise ValueError("issue-form reviewer entry missing")
    required_form = (
        "id: case","id: conclusion","id: source","id: test",
        "id: mechanism","id: applicability","id: limitations",
        "id: independence","id: declarations",
        "SOURCE_CHANGE_SUPPORTED_WITH_LIMITS",
        "SOURCE_CHANGE_INCOMPLETE_OR_CONTRADICTED",
        "ABSTAIN_NEEDS_MORE_PRIMARY_EVIDENCE",
        "not automatically verified human expertise",
        "unadjudicated public source assessment",
    )
    low=form.lower()
    for field in required_form:
        if field.lower() not in low:
            raise ValueError("public reviewer evidence or attestation missing: "+field)
    for case in CASE_IDS:
        if form.count("        - "+case+"\n")!=1:
            raise ValueError("each real case must appear once in form")
        if guide.count(chr(96)+case+chr(96))!=1:
            raise ValueError("source guide omits exact case identity")
    if guide.count("**Case identifier:** ")!=4:
        raise ValueError("four source stage descriptions required")
    patches={}
    for row in source["cases"]:
        for patch in row["patches"]:
            ident=next((i for i,w in indexed.items()
                        if w["repository"]==row["repository"] and w["stage"]==patch["stage"]),None)
            if ident is None or ident in patches:
                raise ValueError("duplicate or unknown real source fix stage")
            patches[ident]=(row,patch)
            common=f"https://github.com/{row['repository']}/blob/"
            for url in (
                common+patch["parent"]+"/"+patch["source_path"],
                common+patch["fix"]+"/"+patch["source_path"],
                common+patch["fix"]+"/"+patch["test_path"],
                row["advisory_url"],
            ):
                expected=2 if url==row["advisory_url"] and row["repository"]=="langchain-ai/langchain" else 1
                if guide.count("("+url+")")!=expected:
                    raise ValueError("missing or inaccurate source/test/advisory permalink: "+url)
    if set(patches)!=set(CASE_IDS) or len(patches)!=4:
        raise ValueError("four exact historical stages required")
    for phrase in (
        "No reviewer has yet been verified as independent",
        "not a blind model holdout",
        "not a multiple-choice answer key",
        "should be viewed after forming your own source analysis",
    ):
        if phrase.lower() not in (guide+" "+form).lower():
            raise ValueError("human review integrity statement missing")
    for unsafe in (
        "independent experts approved falsum",
        "review automatically becomes a gold label",
        "all 20 submitted evaluations accepted by judges",
        "scorer trained and deployed",
    ):
        if unsafe in (guide+" "+form).lower():
            raise ValueError("unfounded source review certification")
    return {
        "status":"PHASE4X_PUBLIC_REVIEW_INVITATION_NOT_INDEPENDENT_GOLD",
        "reviewable_actual_patch_stages":4,
        "distinct_repositories":3,
        "source_test_urls_at_exact_immutable_fix_commits":True,
        "form_requires_original_source_and_test_analysis":True,
        "safe_negative_or_abstain_reviews_allowed":True,
        "independent_expert_reviews_confirmed":0,
        "new_anjoman_eligible_rows":0,
        "trained_model_improvement_proven":False,
        "claim_is_not_an_expert_label":True,
    }


class FourExecutedSourceReviewerPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guide=GUIDE.read_text(encoding="utf-8")
        cls.form=FORM.read_text(encoding="utf-8")
        cls.source=LOCK.read_bytes()
        cls.witness=WITNESS.read_bytes()

    def test_full_exact_source_test_and_advisory_permalinks(self):
        r=inspect(self.guide,self.form,self.source,self.witness)
        self.assertEqual(r["status"],"PHASE4X_PUBLIC_REVIEW_INVITATION_NOT_INDEPENDENT_GOLD")
        self.assertEqual(r["reviewable_actual_patch_stages"],4)
        self.assertEqual(r["distinct_repositories"],3)
        self.assertEqual(r["independent_expert_reviews_confirmed"],0)
        self.assertTrue(r["safe_negative_or_abstain_reviews_allowed"])

    def test_review_not_promoted_to_model_or_network_labels(self):
        r=inspect(self.guide,self.form,self.source,self.witness)
        self.assertEqual(r["new_anjoman_eligible_rows"],0)
        self.assertFalse(r["trained_model_improvement_proven"])

    def test_wrong_test_and_parent_source_sha_refused(self):
        for ident in CASE_IDS:
            w=validated_index(self.witness,self.source)[ident]
            row=next(r for r in load_lock(self.source)["cases"] if r["repository"]==w["repository"])
            s=next(x for x in row["patches"] if x["stage"]==w["stage"])
            for kind in ("source","test"):
                original=f"https://github.com/{row['repository']}/blob/{s['fix']}/{s[kind+'_path']}"
                wrong=original.replace(s["fix"],"0"*40)
                with self.subTest(case=ident,kind=kind),self.assertRaises(ValueError):
                    inspect(self.guide.replace(original,wrong),self.form,self.source,self.witness)

    def test_no_forced_preset_answer_and_abstain_is_allowed(self):
        with self.assertRaises(ValueError):
            inspect(self.guide,self.form.replace(
                "ABSTAIN_NEEDS_MORE_PRIMARY_EVIDENCE",
                "GUARANTEED_PRODUCTION_EXPLOIT"),self.source,self.witness)

    def test_extra_unpinned_form_case_rejected(self):
        changed=self.form.replace("        - langchain-symlink\n","        - invented-project\n")
        with self.assertRaises(ValueError):
            inspect(self.guide,changed,self.source,self.witness)

    def test_form_discloses_unverified_status_and_private_data_safety(self):
        self.assertIn("Do not include secrets",self.form)
        self.assertIn("do **not** need a wallet",self.guide)
        self.assertIn("No reviewer has yet been verified",self.guide)
        self.assertIn("ABSTAIN",self.guide)

    def test_forged_source_lock_or_original_receipt_rejected(self):
        with self.assertRaises(Exception):
            inspect(self.guide,self.form,b'{"fabricated":true}',self.witness)
        data=json.loads(self.witness)
        data["receipts"][0]["raw_source_runtime_receipt_sha256"]="0"*64
        with self.assertRaises(Exception):
            inspect(self.guide,self.form,self.source,json.dumps(data).encode())

    def test_review_not_guided_by_hardcoded_model_or_gold_label(self):
        self.assertNotIn("UPSTREAM_REGRESSION_PASSES|fixed|original",self.guide)
        self.assertNotIn("researcher-preferred",self.form)
        self.assertNotIn("trained-model accuracy reached",self.guide)
        self.assertIn("should be viewed after forming your own source analysis",self.guide)


if __name__=="__main__":
    unittest.main()
