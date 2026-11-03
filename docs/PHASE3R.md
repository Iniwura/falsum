# Phase 3R — Public static Evidence Lab deployment

## Why the release is important

Telegraph Season II's [official judging rules](https://hackathon.telegraphprotocol.com/rules) require an accessible working/reviewer-access link, meaningful inputs and failure cases, a short explanation, reproducibility and actual Telegraph evidence. The Evaluators track also scores ease of adoption and genuine developer activation. An Actions ZIP is useful for reproducibility but not a frictionless demo.

This phase packages the [Phase 3Q Evidence Lab](PHASE3Q.md) for a zero-dependency **static deployment**, with no runtime Python service, server, account, private payload, wallet, model inference or hidden Anjoman evaluation rows. At build time the exact same Python code used in [Phase 3Q CI](../.github/workflows/phase3q-mission-evidence-lab.yml) runs its six fictional before/after functions and writes `public/index.html` and `public/ACTUAL-SYNTHETIC-RUNTIME-PROOF.json`.

### Reproduce the exact deployment output

```bash
git clone https://github.com/Iniwura/falsum
cd falsum
PYTHONPATH=src python3 -m falsum.phase3q_mission_lab --out-dir public
# Open public/index.html, or serve the static public directory.
python3 -m http.server --directory public 8765
```

To rebuild, delete your own previous `public/` directory or use a new `--out-dir`: the experiment intentionally refuses accidental evidence overwrites.

### Host configuration

Root [`vercel.json`](../vercel.json) sets `framework=null`, runs the reproducible Python generator from repository source as the build command, then publishes only `public/`. No dependencies are installed, tokens are configured, or requests are sent to the Anjoman network. It enables basic no-sniff, no-referrer and no-framing headers.

The built HTML is a local data explorer for **captured Python results**; clicking scenario tabs does not rerun the Python code on the host or probe a third-party app. It explicitly labels all examples **fictional and synthetic**. There are no hidden pool row texts, wallet details, private signing messages, accounts or real client cases in the static output. Uploaded confidential data is not accepted by this site.

### Verifying the website

A real publicly accessible deployment requires Git integration plus a successful build and external request check. A passing unit test or `vercel.json` alone is **not** an online deployment.

Inspect the deployment with the [Vercel project](https://vercel.com/dashboard), confirm HTTP 200 on the final URL and static report route, verify desktop/mobile layouts, and test all three tabs using keyboard and touch. If deployment or browser verification fails, report it rather than claiming the site is live.

### Remaining competition work

This public-safe demo reduces judge friction but does **not** prove that a third-party Telegraph mission app used FALSUM or that the quarantined LoRA improved. The 20 real `SECURITY_REVIEW_GENERAL` eligible rows and the [GitHub /submit claim](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) are the separate actual network contribution. Independent developer feedback, adoption, a recorded 2–5-minute walkthrough and the **separate H2 site final submission by 1 December 2026, 23:59 UTC** remain required for a competitive entry.
