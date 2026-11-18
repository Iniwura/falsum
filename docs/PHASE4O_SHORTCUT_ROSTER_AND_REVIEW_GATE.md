# Phase 4O — Adversarial shortcut audit of source-specific review material

**Research status: NOT expert gold, NOT a trained security evaluator, NOT an official Anjoman accuracy score.**  
**Track:** Telegraph Season II Evaluators, `SECURITY_REVIEW_GENERAL`.  
**Scope:** Existing seven source-verified security-fix projects, fourteen previously authored (Phase 4G) review questions, twenty-eight original/reversed A/B presentations.

## What quality failure this measures

FALSUM's original seven A/B questions had an easy answer-style bias: a wording heuristic that picked the answer with fewer universal safety claims agreed with **7/7 researcher-preferred answers**. Phase 4G replaced those with fourteen more precise conditions and one weaker wording-only check. That was an improvement in test design, not evidence that the questions cannot be solved from superficial clues.

A real security reviewer should need the **actual source semantics and relevant context**. A system that selects by answer length, hedging language or overlap with the question may seem to pass without reading code. Phase 4O turns that concern into an adversarial, reproducible **negative-control suite**, explicitly tied to the author hypotheses rather than independently reviewed truth.

## Frozen before scoring

Code: [14 predeclared heuristic definitions](../src/falsum/phase4o_multibaseline_shortcut_audit.py), [adversarial test suite](../tests/test_phase4o_multibaseline_shortcut_audit.py), [source-verifying CI](../.github/workflows/phase4o-material-shortcut-audit.yml).

Each of the 14 predetermined strategies has no upstream source access, no real Telegraph model, no labeled training data, and no prior performance tuning:

- constant A and constant B;
- prefer shorter/longer answers by character count or word count;
- fewer/more absolute certainty words;
- more/fewer cautious conditional words;
- more/less content-word overlap with the question;
- more/fewer syntactic/technical cues.

All fourteen strategies operate across **both A/B positions**. For each, the audit reports: agreement with **14 original researcher hypotheses**; agreement across **28 A/B displays**; and whether choosing the *same text* survives a letter swap. Ties select position A and the resulting position dependence is explicitly visible.

The predeclared **material-quality warning threshold** is **11 of 14** original hypothetical winners, or **22 of 28** A/B displays for a baseline. Any such result sets **`material_quality_gate_passed: false` and `material_promotion_allowed: false`**. The evidence-collection CI still succeeds when it correctly detects a failing material-quality gate: **green CI means the diagnostic ran, not that these cases were approved**. This is a conservative operational trigger, not a statistical significance or security-validity test. Even a passing roster does not prove there are no other shortcuts.

## Observed post-audit results: the answers still need review

The source-verified audit of the **original immutable Phase 4G** casebook exposed a severe answer-only shortcut: **choosing the longer answer agrees with 13 of 14 source-author hypotheses**. This is not a model result or an expert accuracy measurement.

A separately versioned [post-audit six-answer revision](../src/falsum/phase4o_post_audit_revised_material.py) retains the same fourteen questions, exact Git source/test citations and original hypothesis positions, but makes six accurate explanations more concise. The historical casebook remains unchanged, with original and new SHA hashes recorded. This lowers the longer-answer shortcut from **13/14 to 7/14** author agreements.

**However, the revised material is still not ready:** choosing the answer with the most content-word overlap with the question meets the **11/14 high-risk threshold**. That shortcut requires no reading of the code. Further adjustments against this already inspected test roster would overfit the measurement, so the automated quality flag remains **red**. Reviewer source-adjudication or a new independently set and frozen challenge design must follow.

The edits were made **after** observing the length bias and the revision history itself can reveal the author's preference. Therefore neither version is blinded, source-independent gold, sealed holdout, an improved model, or verified Anjoman evaluation quality. FALSUM does not replace its 20 historical Eligible contributor pairs with this edited research material.

## Source and independence boundaries

The workflow first re-fetches and verifies the existing **eight pinned real Git source/test commit pairs** via Phase 3F. It then regenerates Phase 4G's canonical unreviewed casebook from those verified source records. Phase 4O refuses modified question wording, answer SHA hashes, case order, missing swaps, fake expert labels, new row claims, registered adapter claims and source-provenance changes.

The same seven historical projects were already researched by FALSUM. The questions are **not a sealed new holdout**, not independently adjudicated, and not private Anjoman evaluation pairs. The audit reports **zero** new Eligible rows, **zero** expert gold labels, **no** new model inference, **no** improved LoRA, and **no** live network scorer. These limits also apply when all CI tests pass.

If a shortcut flags high agreement, the right next move is to **review and rewrite the answer choices with separate AppSec source adjudication**, not to silently remove the heuristic or raise the threshold. Earlier public questions are retained as historical evidence. Any revised content needs a new committed version, unique hashes and honest before/after shortcut comparison.

## Reproduce

From the FALSUM repository root (Python 3.11+, public GitHub source access):

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4o_multibaseline_shortcut_audit.py' -v

PYTHONPATH=src python -m falsum.phase3f_multifamily_material \
  --old-queue data/real-fix-queue.json \
  --train-queue data/real-fix-train-candidates.json \
  --catalog data/phase2w-applicability-rules.json \
  --out /tmp/falsum-4o-source.json

PYTHONPATH=src python -m falsum.phase4g_reasoning_puzzles \
  --source /tmp/falsum-4o-source.json \
  --out /tmp/falsum-4o-casebook.json \
  --diagnostic /tmp/falsum-4o-original-wording.json

PYTHONPATH=src python -m falsum.phase4o_multibaseline_shortcut_audit \
  --source /tmp/falsum-4o-source.json \
  --casebook /tmp/falsum-4o-casebook.json \
  --out /tmp/falsum-4o-shortcut-audit.json

# A separately versioned, post-audit material revision (NOT blind)
PYTHONPATH=src python -m falsum.phase4o_post_audit_revised_material \
  --source /tmp/falsum-4o-source.json \
  --out /tmp/falsum-4o-post-audit-v2-casebook.json

PYTHONPATH=src python -m falsum.phase4o_multibaseline_shortcut_audit \
  --source /tmp/falsum-4o-source.json \
  --casebook /tmp/falsum-4o-post-audit-v2-casebook.json \
  --out /tmp/falsum-4o-v2-shortcut-audit.json
```

Use different output paths on subsequent runs; write-once evidence files cannot be silently overwritten. The [dedicated Actions workflow](../.github/workflows/phase4o-material-shortcut-audit.yml) publishes the full source proof, casebook, source-sensitive author-hypothesis diagnostic, and all baseline scores as one artifact.

**No demonstration or final entry submission is included in this phase.** Independent AppSec review remains an outstanding release-quality gate.
