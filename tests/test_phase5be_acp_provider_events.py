import copy
import json
import unittest

from falsum import phase5au_solana_anchor_evidence as anchor
from falsum import phase5bb_acp_security_acceptance as gate
from falsum import phase5bd_acp_provider_prepare as provider
from falsum import phase5be_acp_provider_events as events
from falsum.phase5aj_cross_app_evidence import source_bytes


class ProviderEventTests(unittest.TestCase):
    wallet = "0x" + "9" * 40
    buyer = "0x" + "1" * 40

    @classmethod
    def setUpClass(cls):
        cls.raw = source_bytes(next(s for s in anchor.protocol()["sources"]
                                   if s["key"] == "reviewed_advisory"))

    def bundle(self, claim="APPLICABLE", custody=True):
        report_job = dict(schema=gate.SCHEMA, chain_id=84532, job_id="12",
                          intent="SECURITY_REVIEW_GENERAL",
                          target=dict(ecosystem="crates.io", package="anchor-lang",
                                      version="1.0.1", reference=anchor.ADVISORY))
        affected = claim == "APPLICABLE"
        response = dict(claim=claim, verdict="Insecure" if affected else "Secure",
                        vulnerability_count=int(affected),
                        issues=["Scoped advisory"] if affected else [],
                        summary="Scoped applicability claim.")
        report = dict(schema=gate.SCHEMA, chain_id=84532, job_id="12",
                      target=copy.deepcopy(report_job["target"]), claim=claim,
                      response=response, receipt_hash="0x" + "2" * 64)
        trusted = (dict(status="CALLER_VERIFIED", job_digest=gate.digest(report_job),
                        response_digest=gate.digest(response),
                        receipt_hash=report["receipt_hash"],
                        intent=report_job["intent"]) if custody else None)
        requirement = dict(schema=provider.REQUEST_SCHEMA, offering=provider.OFFERING,
                            report_job=report_job, report=report)
        history_entries = [
            {"kind": "system", "event": {"type": "job.created"}},
            {"kind": "message", "from": self.buyer, "contentType": "requirement",
             "content": json.dumps(requirement)},
            {"kind": "system", "event": {"type": "budget.set"}},
            {"kind": "system", "event": {"type": "job.funded"}},
        ]
        history = {"protocol": "v2", "status": "funded", "chainId": 84532,
                   "jobId": "42", "entryCount": len(history_entries),
                   "entries": history_entries}
        def envelope(entry, status, tools):
            return {"jobId": "42", "chainId": 84532, "status": status,
                    "roles": ["provider"], "availableTools": tools,
                    "entry": entry}
        raw_events = [
            envelope({"kind": "system", "onChainJobId": "42", "chainId": 84532,
                      "event": {"type": "job.created", "jobId": "42",
                                 "client": self.buyer, "provider": self.wallet}},
                     "open", []),
            envelope({"kind": "message", "onChainJobId": "42", "chainId": 84532,
                      "from": self.buyer, "contentType": "requirement",
                      "content": json.dumps(requirement)}, "open", ["setBudget"]),
            envelope({"kind": "system", "onChainJobId": "42", "chainId": 84532,
                      "event": {"type": "budget.set", "jobId": "42"}},
                     "budget_set", []),
            envelope({"kind": "system", "onChainJobId": "42", "chainId": 84532,
                      "event": {"type": "job.funded", "jobId": "42",
                                 "client": self.buyer}},
                     "funded", ["submit"]),
        ]
        return raw_events, history, trusted

    def execute(self, claim="APPLICABLE", custody=True):
        raw_events, history, trusted = self.bundle(claim, custody)
        return events.plan_events(
            raw_events,
            provider_wallet=self.wallet,
            histories={(84532, "42"): history},
            custodies={(84532, "42"): trusted},
            advisory_bytes=self.raw,
        )

    def test_accept_reject_hold(self):
        self.assertEqual(self.execute()[1]["action"], "READY_FOR_BUDGET")
        self.assertEqual(self.execute()[3]["action"], "READY_TO_SUBMIT")
        self.assertEqual(self.execute()[3]["recommendation"], "ACCEPT")
        self.assertEqual(self.execute("INAPPLICABLE")[3]["recommendation"], "REJECT")
        self.assertEqual(self.execute(custody=False)[3]["recommendation"], "HOLD")

    def test_no_mutation_is_executed(self):
        for plan in self.execute():
            self.assertFalse(plan["mutation_executed"])

    def test_safety_controls(self):
        raw_events, history, trusted = self.bundle()
        raw_events[1]["entry"]["content"] = "{}"
        plans = events.plan_events(raw_events, provider_wallet=self.wallet,
                                   histories={(84532, "42"): history},
                                   custodies={(84532, "42"): trusted},
                                   advisory_bytes=self.raw)
        self.assertEqual(plans[1]["action"], "HOLD")
        raw_events, history, trusted = self.bundle()
        raw_events[3]["availableTools"] = []
        plans = events.plan_events(raw_events, provider_wallet=self.wallet,
                                   histories={(84532, "42"): history},
                                   custodies={(84532, "42"): trusted},
                                   advisory_bytes=self.raw)
        self.assertEqual(plans[3]["reason"], "SUBMIT_TOOL_NOT_AUTHORIZED_BY_EVENT")


if __name__ == "__main__":
    unittest.main()
