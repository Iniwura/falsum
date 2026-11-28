# Phase 5BP — Public-provider answer and action quality

Phase 5BP adds a bounded measurement that is materially different from the
version-applicability studies. It consumes six genuine, public PR Guard
response captures from the pinned commit
[`99d2e3c93890a8fc083947bde4f21217516b7a5f`](https://github.com/anvithagowda098/pr-guard/tree/99d2e3c93890a8fc083947bde4f21217516b7a5f),
authenticates each Git blob, and evaluates the actual answer claims and
actions.

The frozen roster is in
[`data/phase5bp-public-answer-quality-protocol.json`](../data/phase5bp-public-answer-quality-protocol.json).
The audit stores only provider blob identities, target/code hashes, structured
claim counts and decisions; it does not commit response bodies, payment
objects, receipts or tokens.

## What is measured

Before reading an answer, the audit derives a narrow source reference from the
requested code: SQL query concatenation with `req.query`/`req.params`, shell
command construction with `exec`, and `eval(req.*)` dynamic execution. This
is a reproducible pattern oracle, not human AppSec gold.

For each provider answer, FALSUM checks:

1. evidence excerpts are exact substrings of the requested code;
2. structured findings bind each individual `rule_id` to evidence whose
   metadata names that same rule and to that finding's own recommendation.
   Within a rule, evidence source IDs are assigned one-to-one: duplicate
   findings cannot reuse one source ID, and malformed findings without a rule
   identity fail closed;
3. claimed rule IDs cover the source-derived rules without extras;
4. each risky claim has a remediation recommendation, or a clean/empty result
   carries an explicit bounded-review uncertainty statement; and
5. the answer exposes a scope boundary.

Natural-language answers are evaluated separately: exact code excerpts and
remediation language can support bounded heuristics, but they are explicitly
reported as `natural_language_exact_evidence_only` and never upgraded into
structured per-finding bindings.

The controls are deliberately weaker: verdict-only and finding-presence-only
actions are reported without source-bound evidence or remediation checks.

## Read-only result

Run from the repository root:

```text
PYTHONPATH=src python -m falsum.phase5bp_public_answer_quality \
  --out data/phase5bp-public-answer-quality-result.json
```

The captured run evaluated 6 responses: 3 structured and 3 free-text. The
source-bound policy passed 18/24 checks, produced `BLOCK_OR_REMEDIATE` for
2/6 fully evidenced structured answers, and held 4/6 for review. The controls
only count a raw verdict or the presence of a finding; the free-text clean and
command-injection responses were therefore not promoted to a production
action. Exact answer claim details, quality checks and non-gold boundaries are
in the machine-readable result.

This result is not a claim of human security accuracy, independent adoption,
Telegraph ranking improvement, settlement, customer activity or ACP execution.
It is useful evidence that FALSUM distinguishes complete, target-bound
security actions from confident but incomplete answer surfaces.

The corrected companion artifact is
[`data/phase5bp-public-answer-quality-result-v2.json`](../data/phase5bp-public-answer-quality-result-v2.json).
The original result remains unchanged; V2 adds the explicit per-finding binding
records and binding mode without changing the aggregate score.

## Reproduction

The focused tests are:

```text
PYTHONPATH=src python -m unittest tests.test_phase5bp_public_answer_quality -v
```

The upstream provider repository is public at
[`anvithagowda098/pr-guard`](https://github.com/anvithagowda098/pr-guard), and
the Telegraph security-review family mapping is defined by the official
[`INTENTS.md`](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md).
