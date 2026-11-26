import copy
import unittest
from falsum import phase5bb_acp_security_acceptance as gate
from falsum import phase5au_solana_anchor_evidence as anchor
from falsum.phase5aj_cross_app_evidence import source_bytes


class AcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = source_bytes(next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory"))

    def bundle(self, version="1.0.1", claim="APPLICABLE"):
        job = dict(schema=gate.SCHEMA, chain_id=84532, job_id="1",
                   intent="SECURITY_REVIEW_GENERAL",
                   target=dict(ecosystem="crates.io", package="anchor-lang", version=version, reference=anchor.ADVISORY))
        affected = claim == "APPLICABLE"
        response = dict(claim=claim, verdict="Insecure" if affected else "Secure",
                        vulnerability_count=1 if affected else 0,
                        issues=["Scoped advisory applicability"] if affected else [],
                        summary="Scoped advisory claim.")
        delivery = dict(schema=gate.SCHEMA, chain_id=job["chain_id"], job_id=job["job_id"],
                        target=copy.deepcopy(job["target"]), claim=claim, response=response,
                        receipt_hash="0x" + "1" * 64)
        # Explicitly constructed trusted-caller fixture, NOT a real receipt.
        custody = dict(status="CALLER_VERIFIED", job_digest=gate.digest(job),
                       response_digest=gate.digest(response), receipt_hash=delivery["receipt_hash"],
                       intent=job["intent"])
        return job, delivery, custody

    def decision(self, bundle, raw=None):
        out = gate.evaluate(*bundle, self.raw if raw is None else raw)
        self.assertFalse(out["automatic_settlement_authorized"])
        self.assertFalse(out["settlement_verified_by_falsum"])
        self.assertFalse(out["security_clearance"])
        self.assertFalse(out["live_acp_job_verified"])
        return out["recommendation"]

    def test_frozen_cases(self):
        for case in gate.contract()["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(self.decision(self.bundle(case["version"], case["claim"])), case["expected"])

    def test_identity_and_custody_controls(self):
        for field, value in [("chain_id", 8453), ("job_id", "2"), ("target", {}),
                             ("receipt_hash", "0x"+"2"*64)]:
            with self.subTest(field=field):
                j,d,c=self.bundle()
                d[field]=value
                self.assertEqual(self.decision((j,d,c)), "HOLD")
        for field, value in [("intent", "CODE_REVIEW_GENERAL"), ("status", "UNVERIFIED"),
                             ("job_digest", "0"*64), ("response_digest", "0"*64)]:
            with self.subTest(field=field):
                j,d,c=self.bundle()
                c[field]=value
                self.assertEqual(self.decision((j,d,c)), "HOLD")

    def test_missing_and_contradictory_fields(self):
        for field,value in [("issues", None), ("extra_claim", True), ("verdict", "Secure"),
                            ("summary", "No executable code, configuration files, or system descriptions were supplied for review")]:
            with self.subTest(field=field):
                j,d,c=self.bundle()
                d["response"][field]=value
                c["response_digest"]=gate.digest(d["response"])
                self.assertEqual(self.decision((j,d,c)), "HOLD")

    def test_source_and_reference_controls(self):
        self.assertEqual(self.decision(self.bundle(), self.raw+b" "), "HOLD")
        j,d,c=self.bundle()
        j["target"]["reference"]="GHSA-xxxx-xxxx-xxxx"
        d["target"]=copy.deepcopy(j["target"])
        c["job_digest"]=gate.digest(j)
        self.assertEqual(self.decision((j,d,c)), "HOLD")


if __name__ == "__main__":
    unittest.main()
