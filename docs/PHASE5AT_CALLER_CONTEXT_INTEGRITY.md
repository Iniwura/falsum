# Phase 5AT — caller-context response-integrity extension

Phase 5AR's response-only gate recognizes specific missing-code phrases. A generic Secure/zero-findings response can be identical whether reviewable evidence was available or absent. No response-only policy can distinguish those identical inputs reliably.

The optional Phase 5AT wrapper receives a separate application-owned evidence-availability state. It leaves the existing gate and original historical reports untouched. When an old decision is CLEAN_CANDIDATE, missing/unknown/unrecognized context now requires REVIEW. Existing FLAG and REVIEW decisions are preserved.

## Reproduce

From the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5at_request_context_integrity.py' -v
PYTHONPATH=src python -m falsum.phase5at_request_context_integrity --out constructed-context-report.json
printf '%s' '{"verdict":"Secure","vulnerability_count":0,"issues":[],"summary":"No vulnerabilities were identified."}' | PYTHONPATH=src python -m falsum.phase5at_request_context_integrity --stdin --evidence-state UNAVAILABLE
```

The fixture [was frozen before implementation](https://github.com/Iniwura/falsum/commit/5094212554b52d7b601a1a72e3431c52119cfe5b). It contains 17 author-constructed controls: three identical-response pairs, five additional missing-evidence wording variations, and six other controls. The expected counts are nine unsupported clean candidates for the old gate versus zero for the context gate, with all four clean-candidate controls retained. These are expected policy outcomes until the actual test run succeeds. No historical benchmark or original provider record was changed.

## Integration boundary

- AVAILABLE means the application independently knows relevant reviewable input or scan evidence was available for the exact request. It does not mean a provider actually reviewed it.
- UNAVAILABLE means the application knows the relevant evidence was absent.
- UNKNOWN (or omitted/invalid context) is fail-closed for CLEAN_CANDIDATE.
- Never source this state from the untrusted provider response. JSON fields such as evidence_state do not override the separate context argument. The caller is responsible for authenticating and binding its own evidence state to its request.
- A caller that falsely declares AVAILABLE can still allow a misleading answer. There is no claim of input attestation, semantic accuracy, live inference, outside integration, new human gold, network scoring improvement or security clearance.

The comparison gives the new policy information the response-only gate did not have. A simple independent availability guard composed with Phase 5AR would be equivalent: this is an explicit integration contract and reproducible coverage test, not a superior learned evaluator. Constructed cases are not external or blind labels. No change to the original 129-case comparison or the original three missing-code cases.
