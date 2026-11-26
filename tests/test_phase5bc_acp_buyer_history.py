import copy
import json
import unittest
from falsum import phase5bc_acp_buyer_history as adapter
from falsum import phase5bb_acp_security_acceptance as gate
from falsum import phase5au_solana_anchor_evidence as anchor
from falsum.phase5aj_cross_app_evidence import source_bytes


class BuyerHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = source_bytes(next(s for s in anchor.protocol()["sources"] if s["key"] == "reviewed_advisory"))

    def bundle(self, claim="APPLICABLE"):
        buyer = "0x" + "1" * 40
        job = dict(schema=gate.SCHEMA, chain_id=84532, job_id="42",
                   intent="SECURITY_REVIEW_GENERAL",
                   target=dict(ecosystem="crates.io", package="anchor-lang", version="1.0.1", reference=anchor.ADVISORY))
        affected = claim == "APPLICABLE"
        response = dict(claim=claim, verdict="Insecure" if affected else "Secure",
                        vulnerability_count=1 if affected else 0,
                        issues=["Scoped advisory"] if affected else [], summary="Scoped applicability claim.")
        delivery = dict(schema=gate.SCHEMA, chain_id=84532, job_id="42",
                        target=copy.deepcopy(job["target"]), claim=claim, response=response,
                        receipt_hash="0x"+"2"*64)
        custody = dict(status="CALLER_VERIFIED", job_digest=gate.digest(job),
                       response_digest=gate.digest(response), receipt_hash=delivery["receipt_hash"], intent=job["intent"])
        # Constructed wrapper, not an actual ACP capture.
        entries = [dict(kind="system", event=dict(type="job.created")),
                   {"kind":"message","from":buyer,"contentType":"requirement",
                    "content":json.dumps({k:job[k] for k in ("schema","target","intent")})},
                   dict(kind="system",event=dict(type="budget.set")),
                   dict(kind="system",event=dict(type="job.funded")),
                   dict(kind="system",event=dict(type="job.submitted",deliverable=json.dumps(delivery),
                                                 deliverableHash="0x"+"3"*64))]
        history = dict(protocol="v2",status="submitted",chainId=84532,jobId="42",entryCount=len(entries),entries=entries)
        return dict(buyer=buyer,job=job),history,custody

    def check(self, bundle, expected):
        output = adapter.evaluate(*bundle, self.raw)
        self.assertEqual(output["recommendation"], expected)
        self.assertFalse(output["automatic_settlement_authorized"])
        self.assertFalse(output["live_acp_job_verified"])
        self.assertFalse(output["security_clearance"])

    def test_upstream_contract(self):
        self.assertEqual(adapter.verify_upstream(), 2)

    def test_valid_and_contradicted(self):
        self.check(self.bundle(), "ACCEPT")
        self.check(self.bundle("INAPPLICABLE"), "REJECT")

    def test_binding_and_scope(self):
        for field,value in [("jobId","43"),("chainId",8453),("status","completed"),("protocol","legacy")]:
            with self.subTest(field=field):
                e,h,c=self.bundle()
                h[field]=value
                self.check((e,h,c),"HOLD")
        e,h,c=self.bundle()
        h["entries"][1]["from"]="0x"+"4"*40
        self.check((e,h,c),"HOLD")
        e,h,c=self.bundle()
        h["entries"][1]["content"]="{}"
        self.check((e,h,c),"HOLD")
        e,h,c=self.bundle()
        self.check((e,h,{}),"HOLD")

    def test_lifecycle(self):
        for action in ("duplicate requirement","duplicate submission","premature","terminal","missing delivery"):
            with self.subTest(action=action):
                e,h,c=self.bundle()
                entries=h["entries"]
                if action=="duplicate requirement": entries.insert(2,copy.deepcopy(entries[1]))
                if action=="duplicate submission": entries.append(copy.deepcopy(entries[-1]))
                if action=="premature": entries[3],entries[4]=entries[4],entries[3]
                if action=="terminal": entries.append(dict(kind="system",event=dict(type="job.completed")))
                if action=="missing delivery": entries[-1]["event"].pop("deliverable")
                h["entryCount"]=len(entries)
                self.check((e,h,c),"HOLD")


if __name__ == "__main__":
    unittest.main()
