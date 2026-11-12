# Phase 3Z — source-verified advisory-version evaluation coverage

**12 November 2026 · Research-only. Not a registered model, new eligible network material, or independently approved security labels.**

## Goal

Phase 3Y recorded a real original-model failure (4/8 matches, 0/4 changed-fact reversals). Phase 3Z expands the publicly reproducible *evaluation material* into three genuinely different package projects: docling-core, hydra-core and python-multipart. Each pair compares an affected release and the corresponding published fixed release. The answer choices stay identical within each pair, so a constant A or B scores only 3/6; checking the specific version is necessary.

The provenance is the immutable GitHub Advisory Database at commit **b2a0c7d47ab94089f8774eacdc65ad80f2457170**. Each source JSON is checked against its exact Git blob SHA-1, expected complete advisory affected ranges and the exact public GHSA identity. Two separate release metadata lookups at PyPI verify that the version pairs are published and not yanked.

| Package | GHSA | Earlier release | Fixed release | Observation |
| --- | --- | --- | --- | --- |
| docling-core | [GHSA-vqxf-v2gg-x3hc](https://github.com/advisories/GHSA-vqxf-v2gg-x3hc) | 2.48.3 | 2.48.4 | Catalogued unsafe YAML load conditions; application reachability remains unknown |
| hydra-core | [GHSA-wf6j-7hvr-gr93](https://github.com/advisories/GHSA-wf6j-7hvr-gr93) | 1.3.7 | 1.3.8 | Catalogued legacy blacklist condition; separate prerelease range is preserved but deliberately not evaluated |
| python-multipart | [GHSA-mj87-hwqh-73pj](https://github.com/advisories/GHSA-mj87-hwqh-73pj) | 0.0.25 | 0.0.26 | Catalogued multipart preamble/epilogue issue; application reachability remains unknown |

## Run and reproduce

From the repository root with Python 3.11+:

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -p test_phase3z_catalogue_reversals.py -v
PYTHONPATH=src python -m falsum.phase3z_catalogue_reversals --out /tmp/falsum-phase3z-pinned-source.json
~~~

The unit tests intentionally use **synthetic source fixtures** to verify failure on fabricated Git blobs, corrupted/adulterated source records, mismatched or yanked releases, unapproved URLs, duplicate projects and false release claims. Do not confuse synthetic unit tests with the actual live GitHub/PyPI verifier in the dedicated [Phase 3Z GitHub Actions workflow](../.github/workflows/phase3z-source-catalogue.yml). The live workflow retains its exact source and case JSON for independent reproduction.

This stage verifies **six narrow source-catalogue version facts**, not application vulnerability exploitability, transitive dependencies, remediation sufficiency, general security scores or candidate-model improvements. Public upstream records are not a blind, sealed, or model-pretraining-disjoint holdout. The derived A/B preferences are mechanical facts from the named GHSA range and not independently adjudicated expert training labels.

## Hard release boundary

- Zero new Anjoman submitted or eligible rows are claimed here. The 20 earlier eligible contributor rows are separate.
- Zero independent human labels, trained improvements, model score results, registered evaluator or external developer adoption are claimed.
- Neither original nor retrained quarantined LoRA is promoted.
- Phase 3Z case material remains research-only until independently reviewed and the actual model measurements, if any, have been performed and compared against the same baselines.

This is one engineering deliverable toward the November 17 quality freeze, **not** the hackathon submission. Final work includes expert critique, the strongest valid material-only entry or an independently verified improved adapter, a polished real demo, professional judge documentation, public updates and official website submission.
