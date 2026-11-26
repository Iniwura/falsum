import copy
import json
import unittest
from falsum import phase5bb_acp_security_acceptance as gate
from falsum import phase5bd_acp_provider_prepare as provider
from falsum import phase5au_solana_anchor_evidence as anchor
from falsum.phase5aj_cross_app_evidence import source_bytes


class ProviderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = source_bytes(next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory"))

    def bundle(self, claim="APPLICABLE"):
        buyer = "0x" + "1" * 40
        job = dict(schema=gate.SCHEMA, chain_id=84532, job_id="12",
                   intent="SECURITY_REVIEW_GENERAL", target=dict(ecosystem="crates.io",
                   package="anchor-lang", version="1.0.1", reference=anchor.ADVISORY))
        affected = claim == "APPLICABLE"
        response = dict(claim=claim, verdict="Insecure" if affected else "Secure",
                        vulnerability_count=int(affected), issues=["Scoped advisory"] if affected else [],
                        summary="Scoped applicability claim.")
        report = dict(schema=gate.SCHEMA, chain_id=84532, job_id="12",
                      target=copy.deepcopy(job["target"]), claim=claim, response=response,
                      receipt_hash="0x"+"2"*64)
        custody = dict(status="CALLER_VERIFIED", job_digest=gate.digest(job),
                       response_digest=gate.digest(response), receipt_hash=report["receipt_hash"],
                       intent=job["intent"])
        req = dict(schema=provider.REQUEST_SCHEMA, offering=provider.OFFERING, report_job=job, report=report)
        context = dict(chain_id=84532, job_id="42", buyer=buyer, offering=provider.OFFERING,
                       requirement_digest=gate.digest(req))
        entries = [dict(kind="system", event=dict(type="job.created")),
                   {"kind":"message","from":buyer,"contentType":"requirement","content":json.dumps(req)},
                   dict(kind="system",event=dict(type="budget.set")),
                   dict(kind="system",event=dict(type="job.funded"))]
        history = dict(protocol="v2", status="funded", chainId=84532, jobId="42",
                       entryCount=len(entries), entries=entries)
        return context,history,custody

    def run_bundle(self, bundle):
        out=provider.prepare(*bundle,self.raw)
        self.assertFalse(out["automatic_settlement_authorized"])
        self.assertFalse(out["live_acp_job_verified"])
        return out

    def check(self,bundle,expected):
        out=self.run_bundle(bundle)
        self.assertTrue(out["prepared"])
        delivery=out["deliverable"]
        self.assertEqual(delivery["verification_job"]["job_id"],"42")
        self.assertFalse(delivery["history_authenticated_by_falsum"])
        self.assertFalse(delivery["report_evaluation"]["security_clearance"])
        self.assertEqual(delivery["report_evaluation"]["recommendation"],expected)
        self.assertFalse(delivery["report_evaluation"]["settlement_verified_by_falsum"])

    def test_upstream(self):
        self.assertTrue(provider.verify_upstream())

    def test_scoped_decisions(self):
        self.check(self.bundle(),"ACCEPT")
        self.check(self.bundle("INAPPLICABLE"),"REJECT")
        e,h,c=self.bundle()
        self.check((e,h,None),"HOLD")
        c["receipt_hash"]="0x"+"3"*64
        self.check((e,h,c),"HOLD")

    def test_job_lifecycle_and_context(self):
        for field,value in [("jobId","43"),("chainId",8453),("status","open"),("protocol","legacy")]:
            with self.subTest(field=field):
                e,h,c=self.bundle()
                h[field]=value
                self.assertFalse(self.run_bundle((e,h,c))["prepared"])
        for action in ("wrong buyer","duplicate","submitted","changed requirement","wrong offering","injected custody","same job"):
            with self.subTest(action=action):
                e,h,c=self.bundle()
                entries=h["entries"]
                if action=="wrong buyer": entries[1]["from"]="0x"+"4"*40
                if action=="duplicate": entries.insert(2,copy.deepcopy(entries[1]))
                if action=="submitted": entries.append(dict(kind="system",event=dict(type="job.submitted")))
                if action=="wrong offering": e["offering"]="anotherService"
                if action=="changed requirement": entries[1]["content"]="{}"
                if action in ("injected custody","same job"):
                    req=json.loads(entries[1]["content"])
                    if action=="injected custody": req["trusted_custody"]=c
                    else: req["report_job"]["job_id"]="42"
                    entries[1]["content"]=json.dumps(req)
                    e["requirement_digest"]=gate.digest(req)
                h["entryCount"]=len(entries)
                self.assertFalse(self.run_bundle((e,h,c))["prepared"])


if __name__=="__main__":
    unittest.main()
