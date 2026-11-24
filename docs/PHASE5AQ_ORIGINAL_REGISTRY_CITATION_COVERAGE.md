# Phase 5AQ — exact registry-linked CWE citation coverage

The Phase 5AP original-label audit showed why a negative verdict cannot demonstrate annotated vulnerability identification. This follow-up evaluates a narrow, independently sourced reference check, **not** semantic detection accuracy. The selection rule is all vulnerable entries in the existing 129-case manifest whose original source URL directly names an SWC registry documentation entry. It excludes other origin types, including GitHub test-case URLs whose registry identity would need an additional mapping. Source and output were inspected before implementation, so the analysis is retrospective.

Authenticate the same original ledger, manifest, receipt archive and SmartBugs annotation file, plus five [historical SWC Registry documents](https://github.com/SmartContractSecurity/SWC-registry/tree/1b6227074ecd180b374e4844153afdda0332f979/entries/docs). Read their actual Relationships section, not an invented category crosswalk. SWC Registry is no longer actively maintained. These original relationships are SWC-101 → CWE-682; 105 → 284; 112 → 829; 118 → 665; 124 → 123.

## Source-inspected result (fresh dedicated CI required)

| Observation | Count |
| --- | ---: |
| Selected direct registry-linked cases | 11 |
| Recorded security answers | 10 |
| Negative verdicts | 10 |
| Exact registry-linked CWE citation observed in issues or summary | 0 |
| Explicit pre-request input-limit hold | 1 |

Ten of eleven selected cases have no recorded name/comment hint. This is a citation-coverage diagnostic: it does not assert ten semantically incorrect reviews. A narrower CWE (for example CWE-190 versus the registry's CWE-682) or correct natural-language finding can be valid without an exact citation. CWE hierarchy relationships, semantic correctness and line localization are not evaluated. An exact citation by itself would not establish correctness either. The result applies only to the source-defined 11-case slice, not all 107 selected vulnerable contracts.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5aq_swc_citations.py' -v
PYTHONPATH=src python -m falsum.phase5aq_swc_citations --out phase5aq-report.json
```

The report includes only case identifiers, registry IDs, recorded CWE IDs, verdict/availability and citation state. Original source identity and previously frozen aggregate metrics are preserved. No new inference, security clearance, ranking improvement, expert gold or outside adoption is claimed.
