# Phase 3S — Reference-led editorial Evidence Lab

**Visual direction:** [Firma by Anton Drukarov](https://firma-template.framer.website/), used for overall creative direction rather than copying its proprietary content, photos, branding or assets. The redesign adopts an almost-white canvas, deep black editorial serif headlines, generous negative space, giant typographic branding, asymmetric project case studies and subtle coral accents. The result is a distinct FALSUM security-research site with actual interactive evidence.

## What changed

- **Editorial introduction:** “Look beyond the claim.” The first screen prioritizes a coherent thesis and legible hierarchy rather than a generic SaaS hero.
- **Three oversized, click-through case studies:** Exchange authorization, Model Economy callback authenticity, and Web3 off-chain replay prevention. Each opens the exact selected case inside the Evidence Lab.
- **Evidence Lab:** Three scenario tabs plus a real before/after switch. The displayed state, legitimate-control checks, precise Python source code and SHA256 fingerprint derive from actual local Python executions. The browser is a static **viewer**, not a fake runnable evaluator or real-world scanner.
- **Three-part editorial methodology:** Actual source, real network contribution and strictly stated limitations.
- **Production quality:** Responsive sections and mobile navigation, keyboard-accessible actual buttons, labels for live result updates, focus-visible controls, reduced-motion support, no external assets/fonts or scripts, and a restrictive CSP.
- **Privacy:** No private Anjoman qualification questions, answers, secrets, wallet identifiers, row hashes, authenticated views or customer material are included. The 20 eligibility rows are reported as an **account UI observation** and the bounty approval remains pending.

## Implementation

[The editorial HTML template](../src/falsum/templates/firma_editorial_evidence_lab.html) is wholly local, containing structural content, detailed responsive CSS and vanilla JavaScript for controls. [The existing Python proof generator](../src/falsum/phase3q_mission_lab.py) now reads the design template and injects a single, JSON-escaped representation of its actual captured report.

The source snippets shown in the interface are obtained using `inspect.getsource` for the *very Python implementations that ran*. The source SHA256 fingerprints are computed from those exact text bytes. Missing/extra data placeholders cause generation to fail closed; the embedded JSON escapes <, > and & so executable source text cannot inject an HTML tag or terminate the inert JSON script.

Every case demonstrates one unsafe synthetic behavior before, its prevention after, and an unchanged positive control. There is no model inference or third-party mission integration hidden behind the UI.

## Run locally

```bash
git clone https://github.com/Iniwura/falsum
cd falsum
PYTHONPATH=src python3 -m falsum.phase3q_mission_lab --out-dir phase3s-preview
python3 -m http.server --directory phase3s-preview 8765
```

Open `http://localhost:8765`, select each case, switch between Before/After, and inspect the actual source. The `ACTUAL-SYNTHETIC-RUNTIME-PROOF.json` artifact contains the full corresponding report, including the exact public source code snippets. The output directory must not already exist.

## Real validation gates

- `PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3q_mission_lab.py -v`
- `PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3r_deployment.py -v`
- `PYTHONPATH=src:tests python -m unittest discover -s tests -p test_phase3s_editorial_evidence_lab.py -v`
- [Phase 3S CI](../.github/workflows/phase3s-editorial-ui.yml) runs those suites on Python 3.11, 3.12 and 3.13, compiles the exact Python generator, executes all three local tests, checks source-code SHA identities, checks the actual generated browser JavaScript with Node, and saves the site as artifacts for visual and functional inspection.

**Website deployment evidence** is a separate requirement: after green CI, publish the new main-branch build to [FALSUM Evidence Lab](https://falsum-evidence-lab.vercel.app). Verify both live HTTP pages, exact source commit, and all three browser controls. No visual/browser QA claim should be made before those checks pass.

## Competition boundaries

The content is public-safe original creative work inspired by the **design system** of Firma. It does not reuse Framer photography or proprietary typography. The user’s actual contribution remains **20 Anjoman-eligible SECURITY_REVIEW_GENERAL pairs** with an already posted GitHub bounty claim. A responsive editorial demo can improve judge experience but does **not** establish an approved bounty, registered evaluator model, independent security labels or adoption by another mission. Those need separate, real evidence.
