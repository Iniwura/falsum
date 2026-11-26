# FALSUM for ACP — scoped acceptance candidate

## Scope and collaborator interface

This is a read-only recommendation engine for **one requested advisory applicability claim**, not general audit acceptance. It reuses the original reviewed Anchor advisory for crates.io anchor-lang, including the exact affected interval. It returns ACCEPT for a corroborated scoped claim, REJECT for a contradicted scoped claim, HOLD for missing/unbound or out-of-scope evidence. Never interpret ACCEPT as contract safety or authorization to settle. Other security reports remain out of scope.

Inputs are three separate JSON documents:
- Trusted buyer-side job: schema, chain_id, decimal-string job_id, target (ecosystem, package, version, reference), intent.
- Seller deliverable: schema, chain_id, job_id, target, claim, response (verdict, vulnerability_count, issues, summary, claim), receipt_hash.
- Trusted buyer-side purchase custody: status CALLER_VERIFIED, job_digest, response_digest, receipt_hash, intent. Digests use SHA256 over sorted compact ASCII JSON. This must be produced from an independently verified purchase record and actual response, never extracted from seller-controlled input. The mapping from the external receipt to the request and response is the caller's responsibility. FALSUM does not independently verify onchain settlement or ACP state.

```sh
PYTHONPATH=src python -m falsum.phase5bb_acp_security_acceptance --job job.json --deliverable delivery.json --trusted-custody custody.json
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5bb_acp_security_acceptance.py' -v
```

The optional --advisory path accepts the exact pinned bytes for offline operation. No wallet, signer, funds, or paid model calls required. Input/schema errors must be handled as HOLD by the host. The recommendation includes exact input digests so a caller can check they still match before any independent approval decision.

## Virtuals integration boundary

Current upstream [ACP CLI](https://github.com/Virtual-Protocol/acp-cli) documents read-only job history, provider submit, and buyer complete/reject commands. The integration should read authenticated job history, normalize the agreed requirement and seller deliverable, independently obtain the purchase receipt and response through the collaborator's trusted Telegraph client, then invoke the engine. Do not pass seller-supplied custody. Do not automate payment release; the authorized buyer reviews the recommendation and independently verifies current job status. No ACP schema compatibility or registered evaluator role is asserted by this local interface.

## Next required external evidence

A consenting Virtuals builder maps one actual job to this bounded contract, supplies actual receipt and answer custody, and demonstrates correct, contradicted and incomplete deliverables. Record real job IDs, transaction evidence, raw-source identity and limitations. The local fixtures are constructed, and no live ACP job, paid purchase, outside adoption, network ranking improvement, or model-accuracy improvement has been established. Do not ask anyone to fund a wallet before the exact permitted sandbox flow is confirmed.
