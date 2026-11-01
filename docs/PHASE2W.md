# Phase 2W — Evidence-first source-bound applicability review

**Implemented and verified 1 November 2026. Research-only.**

Earlier FALSUM reward-model training showed improved in-sample AI preference agreement but failed to reverse judgments on source-separated deployment-context comparisons. Phase 2W changes the method: **before** scoring a security finding, inspect named exposure preconditions backed by immutable file and source identity.

## What is implemented

- [11 source-pinned vulnerability families](../data/phase2w-applicability-rules.json), across Requests, aiohttp, Jinja2, Axios, Starlette, urllib3, Django, Express, Tornado, Undici and Python websockets. There are **22 explicit necessary-condition questions**, two per vulnerability. The rules are AI-authored research hypotheses, not expert-reviewed rules.
- [Evidence-first proof gate](../src/falsum/phase2w_proof_gate.py): verifies a submitted application's file SHA-256 and exact 1-based cited line text; guards against symlinks, absolute paths, traversal, oversized files, unknown conditions, forged source identities and false release-status promotion. Binds source records to their pinned upstream Git SHA and blob.
- [Actual application excerpt capture command](../src/falsum/phase2w_capture.py): takes developer assertions and local files, generates byte-identical citations and an immutable review manifest without modifying the application.
- [Synthetic research demonstration](../src/falsum/phase2w_synthetic_demo.py): 44 generated fixture cases across all 11 source families. These are **not production applications or ground truth**.
- [20 adversarial proof tests](../tests/test_phase2w_proof_gate.py) plus [9 real-source capture tests](../tests/test_phase2w_capture.py).

## Four conservative statuses

| Research output | Required logic | Security interpretation |
| --- | --- | --- |
| CONDITIONALLY_APPLICABLE_REVIEW_CANDIDATE | Every prerequisite has a verified excerpt carrying an assertion of presence | Flag a **candidate for human review**, never a confirmed exploit |
| APPLICABILITY_PRECONDITION_CONTRADICTED | A necessary prerequisite is asserted absent, without conflicting evidence | The **scoped** exploit theory is not established, not proof the application is secure |
| INSUFFICIENT_APPLICATION_EVIDENCE | A prerequisite has no submitted assertion | Abstain and request the missing source/context |
| CONFLICTING_APPLICATION_CLAIMS | The same prerequisite has both present and absent assertions | Abstain, identify both citations and investigate the conflict |

Every output sets human_review_required=true, confirmed_security_finding=false and network_eligible=false. A correct SHA-256 and exact quote means *the same bytes were reviewed*: it does **not** prove that the submitter's assertion about those bytes is true. Absence of an exploit cannot be established merely because a function was not found in a short source excerpt.

### Run against your own application

From the FALSUM checkout, choose a source case in the applicability rules catalog. For example, real-requests-proxy-auth requires evidence about credentialed_proxy and https_redirect.

Save a file named claims.json with the **line ranges inside your actual application**:

~~~json
{
  "status": "SUBMITTER_ASSERTIONS_UNREVIEWED",
  "claims": [
    {
      "requirement_id": "credentialed_proxy",
      "claim": "present",
      "path": "app.py",
      "line_start": 3,
      "line_end": 5
    },
    {
      "requirement_id": "https_redirect",
      "claim": "absent",
      "path": "app.py",
      "line_start": 12,
      "line_end": 14
    }
  ]
}
~~~

These values are manual, **unreviewed interpretations**. Paths are relative to your application's root, not the FALSUM repo. Negative assertions require special caution because a short excerpt rarely proves a behavior is absent throughout an application.

Capture the actual bytes and citations:

~~~bash
PYTHONPATH=src python -m falsum.phase2w_capture \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --case-id real-requests-proxy-auth \
  --claims claims.json \
  --root /path/to/your/app \
  --out /tmp/falsum-captured.json
~~~

Create an input batch from the captured object. It must be the *full* object, not an invented path or identifier:

~~~python
import json
from pathlib import Path

capture = json.loads(Path("/tmp/falsum-captured.json").read_text())
batch = {
    "schema_version": 1,
    "status": "UNREVIEWED_APPLICATION_EVIDENCE_BATCH",
    "research_only": True,
    "scenarios": [capture],
}
Path("/tmp/falsum-batch.json").write_text(json.dumps(batch, indent=2))
~~~

Run the evidence gate:

~~~bash
PYTHONPATH=src python -m falsum.phase2w_proof_gate \
  --catalog data/phase2w-applicability-rules.json \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --fresh-spec data/phase2u-fresh-transfer-cases.json \
  --batch /tmp/falsum-batch.json \
  --root /path/to/your/app \
  --out /tmp/falsum-report.json
~~~

This output contains source identities, conditional applicability status and each hash-and-line-bound assertion. If the source file changes after evidence capture, the gate refuses to process stale evidence.

## Verified CI evidence

[Successful end-to-end workflow 41286462954](https://github.com/Iniwura/falsum/actions/runs/41286462954):

- **20** proof-gate adversarial tests, **9** application capture tests, **9** project isolation tests and **8** upstream source-check tests passed.
- **44/44 synthetic scenarios** processed, with 11 examples in each of the four decision categories.
- **16/16** historical Git-pinned source/test file transitions reverified for the original eight source projects. The three remaining newer projects had their six source/test file transitions verified in [Phase 2U run 41284227213](https://github.com/Iniwura/falsum/actions/runs/41284227213).
- The actual application capture CLI was executed on a separate illustrative Python file. It captured exact hashes/lines, produced an application evidence manifest and passed the gate, but did **not** demonstrate an actual credential leak.

[Archived execution packet, synthetic inputs and original upstream patch data](https://github.com/Iniwura/falsum/actions/runs/41286462954/artifacts/13075692037).

## Remaining weaknesses and Phase 2X

The code verifies that a developer's cited excerpt **exists** and has not changed; it **does not automatically validate the interpretation** of the excerpt. This is a security-critical distinction. For example, someone could assert a prerequisite is absent while citing a source line that appears to show the opposite: the current gate records the disagreement for human review, not semantic proof.

The next substantial product upgrade is **machine-verifiable observations** for narrowly scoped rules, such as a literal static configuration flag or constant call argument parsed with an AST, plus explicit abstention on dynamic configuration and call graphs. Those observations should be checked against real application tests and never be silently promoted to proof of full exploitability. Subsequently, candidate review answers can be checked against observed application prerequisites rather than their surface wording.

FALSUM remains research-only: zero confirmed exploited applications, zero independent expert-approved preference pairs, zero accepted Anjoman evaluation rows and no registered Telegraph evaluator. A technically runnable WASM checkpoint does not change that quality status.
