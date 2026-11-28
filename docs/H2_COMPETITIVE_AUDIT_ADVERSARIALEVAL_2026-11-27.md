# Competitive audit — AdversarialEval

This is a read-only comparison against
[`Ritapossible/AdversarialEval`](https://github.com/Ritapossible/AdversarialEval/tree/09f9fa4a584b513720b215731baf54187039ac10)
at commit
[`09f9fa4a584b513720b215731baf54187039ac10`](https://github.com/Ritapossible/AdversarialEval/commit/09f9fa4a584b513720b215731baf54187039ac10).
It records what the public evidence supports; it does not assign a fabricated
numeric competitor score.

## Where AdversarialEval is stronger

The competitor has the clearest evidence of independent activity and a live
application outcome:

- its README reports **164 eligible attested** `SECURITY_REVIEW_GENERAL` rows,
  a paid-market benchmark with **3,680 calls**, and a live Dependency.Guard
  Mind workflow;
- its pool includes independently authored material and its registration
  protocol freezes a candidate, requires two reviewers, measures shortcut
  judges and reports Wilson intervals;
- its live workflow reports verified answers blocking unsafe versions and a
  compact “Spot the Flaw” demo, which gives judges an immediate customer-shaped
  outcome;
- its code-review and Solana/dependency examples show answer ranking, provider
  comparison and workflow-level decisions rather than only repository tests.

Those are real advantages for Evaluators useful coverage, external validation
and judge experience. FALSUM must not imply that its 20 reported eligible rows,
source replay or internal mission tests are equivalent to that live customer
workflow.

## Where the competitor is weaker

The same public evidence also exposes limits that FALSUM can address without
imitating the product surface:

- its own 40-pair independent test reports **77.5%**, below its pre-registered
  80% bar and Wilson lower-bound requirement; the owner registered the result
  as an explicit override;
- its leave-one-family-out report shows roughly **37–39%** transfer on unseen
  failure types, so the public benchmark is not evidence of broad security
  generalization;
- its Dependency.Guard result is close to free OSV lookup on the package/version
  examples, limiting novelty there;
- provider independence is concentrated: the audit reports 37 miners but only
  13 payout addresses, with two addresses running 26 miners.

These are not disqualifications. They are reasons to separate market scale,
workflow usefulness and semantic validity rather than let any one headline
number stand for all three.

## FALSUM's defensible differentiation

FALSUM should compete on a narrower property the public competitor evidence
does not demonstrate as completely:

1. exact source, target, transport and response-identity binding;
2. immutable advisory and registry evidence snapshots, including PEP 440 and
   SemVer prerelease/disjoint-interval semantics;
3. explicit `UNKNOWN_OR_INSUFFICIENT` handling for malformed or unsupported
   ranges instead of a safe-looking fallback;
4. actual answer-claim, evidence-anchor, remediation-action and uncertainty
   checks on public provider responses; and
5. a strict separation between paid/HTTP observations, custody/receipt proof,
   semantic correctness, customer adoption and official network registration.

Phase 5BP makes the fourth point measurable: six authenticated public response
blobs produce 18/24 source-bound integrity checks, two fully supported actions
and four review holds. The structured responses pass the complete contract;
incomplete free-text responses do not. This is bounded static-pattern evidence,
not human AppSec gold, and is not promoted to a ranking claim.

## Competitive decision

Do not copy the competitor's live-market or provider-volume story. FALSUM can
genuinely outperform by being the entry judges trust when the question is:
“Can this evaluator prove that its answer belongs to this exact target, source,
version and action, and abstain when it cannot?” The remaining gap is genuine:
FALSUM still lacks a verified independent customer integration, accepted live
adapter registration and independent human AppSec adjudication.

The authoritative Telegraph context remains separate: bounty
[`#96`](https://github.com/telegraphprotocol/bounties/issues/96) and
[`INTENTS.md`](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md)
map `SECURITY_REVIEW_GENERAL` to the `SECURITY_REVIEW` family, but that mapping
does not prove maintainer acceptance or live adapter registration.
