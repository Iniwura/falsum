# Phase 5AP — original label provenance and selection-aware category coverage

The 129-case Gig Guard comparison uses 107 SmartBugs Curated vulnerable contracts and 22 audited controls. The previous aggregate 89/107 flag count is correct for the **selected population**, not the full original dataset or a vulnerability localization score.

FALSUM adds a separate retrospective audit of the [original SmartBugs annotation file](https://github.com/smartbugs/smartbugs-curated/blob/230e649123477eff332742a59a1c7cc6dc286cab/vulnerabilities.json), Git blob `4771a256d0111997451dd323e6306b480da78794`. Match exact source revision/path, primary category, annotation line set and original source URL for every selected vulnerable manifest entry. Use the already authenticated 129-case ledger, manifest and receipt archive; retain the original selection, labels, and policy metrics. Categorize answer availability using Phase 5AN. The metadata and source selection were inspected before implementation; this is retrospective, not blind.

## Original inspected counts (dedicated CI still required)

All 107 selected vulnerable entries match the original annotation metadata. Of 143 original contracts, 36 are outside the app's selection. The largest exclusion is unchecked-low-level-calls: 52 original, 20 selected, 32 omitted. Of the 20 selected, 12 have recorded answers, one recorded failure and seven preflight holds. The 12 are flagged by verdict-only, and two of those have count-only PASS predictions. The other 32 contracts were not evaluated in the published run; they are **not** false negatives.

| Primary category | Original | Selected | Recorded answers | Verdict flags |
| --- | ---: | ---: | ---: | ---: |
| Access control | 18 | 16 | 15 | 15 |
| Arithmetic | 15 | 15 | 13 | 13 |
| Bad randomness | 8 | 7 | 4 | 4 |
| Denial of service | 6 | 6 | 5 | 5 |
| Front running | 4 | 4 | 3 | 3 |
| Other | 3 | 3 | 2 | 2 |
| Reentrancy | 31 | 30 | 29 | 29 |
| Short addresses | 1 | 1 | 1 | 1 |
| Time manipulation | 5 | 5 | 5 | 5 |
| Unchecked low-level calls | 52 | 20 | 12 | 12 |
| **Total** | **143** | **107** | **89** | **89** |

A flag does not establish that the annotated vulnerability type or line was identified. Do not map arbitrary CWE text to categories without a defensible external crosswalk or claim the 107 source code files were independently rehashed. The source annotation file is independently authenticated; the selected code bytes and actual submitted inputs are not separately verified here. The 22 audited controls are not certified bug-free and are not in the SmartBugs denominator. No new inference, blind expert label, full-dataset recall, network ranking uplift, or outside adoption is claimed.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_phase5ap_upstream_selection.py' -v
PYTHONPATH=src python -m falsum.phase5ap_upstream_selection --out phase5ap-report.json
```

The report includes all ten category denominators, selection gaps, answer/failure/hold counts, count-only PASS counts, no-hint counts and original omitted paths. It is reproducible without a wallet, API token or paid call.
