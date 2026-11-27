# Official Evaluators rubric and technical minimum

Verified 27 November 2026 from the current [official Season II rules page](https://hackathon.telegraphprotocol.com/rules).

The public page renders the track selector client-side. The Evaluators
criterion object in the official rules page bundle was checked at:

`https://hackathon.telegraphprotocol.com/_next/static/chunks/app/(s2)/rules/page-786441c38e802980.js`

Observed bundle identity at verification: UTF-8 byte length `58262`,
SHA-256 `91c72d3f8dee162a9bc3a17aa90306cfc5b2dba08bc5d38055485ecdab119844`.
The hash is a provenance note for this inspection, not a replacement for the
official rules URL.

## Evaluators-specific scoring

| Criterion | Points | Technical interpretation for FALSUM |
| --- | ---: | --- |
| Measurement validity, quality discrimination, and baseline evidence | **40** | Judges use repeatable methods, appropriate unseen examples, credible reference answers or defensible checks, and a comparable baseline where one exists. **Technical minimum: 28/40.** |
| Integrity and robustness | **15** | Provenance binding, fail-closed behavior, adversarial resistance, safe handling, and protection against unsupported claims. |
| Reproducibility and protocol compatibility | **10** | Re-runnable evaluator/material behavior and compatibility with Telegraph's evaluation pipeline and Intent shape. |
| Useful evaluation coverage and demonstrated improvement | **10** | New coverage, better measurement accuracy, better Provider distinction, more reliable reference material, or an underserved Intent; do not claim ranking change without evidence. |
| Documentation and integration clarity | **5** | Clear Intent, material/adapter version, inputs, outputs, limits, and integration instructions. |
| Organic growth, education, and developer activation | **20** | Content/education, ease of adoption, organic distribution, and community activation. |
| **Total** | **100** | Entry must also satisfy the common Section 5 bar and the official submission requirements. |

This replaces the previously used Apps & Agents-shaped table. The page's
default client-rendered summary can show the Apps & Agents-shaped categories,
but an Evaluators entry's technical gate is the explicit **28/40
measurement-validity minimum**, not 24/35. The official delivery order is also track-specific: distinct
commercial missions, distinct H2 app workflows, independently verified
mission-critical Intent needs, then combined technical quality. Evaluator ties
prefer proven measurement improvement or valuable new coverage, then validity.

## Authoritative Intent mapping and material gate

The official [bounty #96](https://github.com/telegraphprotocol/bounties/issues/96)
and the current [INTENTS.md catalogue](https://github.com/telegraphprotocol/bounties/blob/main/docs/INTENTS.md)
explicitly map the child Intent `SECURITY_REVIEW_GENERAL` to the judgment
family `SECURITY_REVIEW`, whose adapter is registered at the family level.
The catalogue defines the response shape as `verdict`,
`vulnerability_count`, `issues`, and `summary`, and lists question-pair
material with an adapter on `SECURITY_REVIEW`.

This resolves the former naming/family mapping gap. It does **not** establish
maintainer acceptance of FALSUM's contribution, live adapter registration, or
that the network is currently using these rows for ranking.

The official [evaluation-material requirements](https://anjoman.ai/docs/scoring/contribute-evaluation-data)
say that judgment material is question/better-answer/worse-answer data;
`eligible` means the row is in a frozen snapshot and is usable by the network.
Question material needs at least five contributors before an Intent's pool is
used, and row content is never returned by the public status endpoint. Bounty
#96 separately states that an individual contributor's part counts once their
rows are `eligible`, while maintainer approval and network use are separate
decisions.

FALSUM's current read-only status is **20/20 eligible rows** for the
operator-reported Privy address. That satisfies the individual contribution
gate evidenced by #96, but it does not prove the five-contributor pool gate,
active-snapshot use, maintainer acceptance, cryptographic ownership, or live
adapter registration.

FALSUM's strongest eligible shape is evaluation material: source-authenticated
reference checks, version-boundary logic, response-integrity controls, a
frozen public-provider holdout, and repeatable tests. The quarantined model
experiments are not presented as a released evaluator adapter.
