# Phase 3U — Minimal FALSUM review interface

## Why

The user rejected the earlier Phase 3T UI and provided [Jett](https://gojett.framer.website/) as a visual reference, alongside the standing product standard: **simple purpose, architecture, design and implementation; no taglines or text that only explains a confusing layout**.

The [Jett Framer listing](https://www.framer.com/marketplace/templates/jett/) emphasizes near-black, oversized condensed editorial typography, high-contrast work, restrained motion and the work itself as the focus. FALSUM uses that direction, without copying Jett's portfolio, media, photography, proprietary source or brand.

## What changed

The experience is one clear task:

**PICK THE BETTER REVIEW.**

The page starts immediately with the first case. The person can read the situation, choose A or B, see a short factual correction, reveal actual local Python test results and advance. The existing three public fictional cases, real source hashes, source disclosure, score and restart remain functional. There's no separate marketing hero, three-step tutorial, badge system, dashboard, fake metrics or decorative illustration.

The layout relies on one dark monochrome palette, editorial Impact/Arial Narrow typography, strong hierarchy and thin rules. The little color that exists is a **real semantic state**: a better review, a wrong review, and a patched-vs-unpatched result. On narrow mobile widths, the same task is stacked without horizontal overflow. Keyboard activation, focus rings, reduced motion and screen reader feedback remain included.

Advanced developer details stay behind a disclosure. All live content is generated from the same measured public Python proof and protected from script-breakout injection.

## No regression in claims or network data

- Sample A/B reviews are **handwritten public examples**, not outputs from a registered or live AI model.
- All three examples run **fictional Python code** during static site build; results are real for those fixtures, not third-party mission software.
- No hidden Anjoman questions/answers, wallet identifiers or row hashes appear in the public build.
- The 20 previously eligible Anjoman evaluation pairs and bounty /submit remain **separate and unchanged**.
- The judge should not infer production vulnerability, expert-reviewed accuracy, external adoption, bounty approval or a hackathon win.

## Validation before shipping

1. Preserve original Python runtime, source SHA256, positive-control, fail-closed and privacy tests on Python 3.11–3.13.
2. Run the Playwright full three-case browser journey with deliberate incorrect answer, right answers, evidence reveal, result, score and restart.
3. Check desktop, mobile 390px and narrow 320px for horizontal overflow and console errors; verify keyboard and touch.
4. Verify deployed source commit on Vercel matches the merged GitHub main SHA, and that both HTML and JSON serve HTTP 200. Avoid claiming manual pixel-by-pixel QA without a proper screenshot review.

The implementation remains a single static HTML/CSS/JS template plus the existing Python capture utility. No new framework, dependency, API backend or runtime service is introduced.

## Judge path

Open the FALSUM public site. Read the first incident. Choose A or B. Reveal result. Repeat twice. The result screen finishes the exercise. Developers can inspect the exact executed function and SHA256, or reproduce everything from [Phase 3Q](PHASE3Q.md). The source of truth remains the actual Python report, not the browser's animation.
