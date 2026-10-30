# Phase 2c: application-security scenario casebook (DRAFT)

This casebook adds **12 non-submittable, hypothetical** security-review comparisons beyond dependency-version checks. These are *test situations* derived from public security guidance, **not observations of real vulnerabilities**, verified PRs, miner responses, or independent human security reviews.

| Category | Cases | Main failure being challenged |
| --- | ---: | --- |
| Configuration | 2 | Treating local debug settings as active production exposure, or overlooking production debug mode |
| Secret handling | 4 | Treating placeholders as leaked credentials, ignoring confirmed production-key disclosures, or assuming transformed secret values are always masked |
| Request boundaries | 2 | Ignoring arbitrary outbound destinations or overclaiming safety from an allowlist |
| Workflow permissions | 2 | Ignoring write authority during untrusted builds or inventing access beyond `contents: read` |
| TLS validation | 2 | Overlooking certificate validation disabled in production or inferring production impact from isolated test fixtures |

The examples are grounded *conceptually* in these public primary sources, but the URLs have **not** been archived or hash-pinned for these draft cases:

- [Django deployment checklist](https://github.com/django/django/blob/main/docs/howto/deployment/checklist.txt): production DEBUG and signing-secret hygiene.
- [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html): trust boundaries, redirection, allowlists, and layered defenses.
- [GitHub Actions secure-use guidance](https://github.com/github/docs/blob/main/content/actions/reference/security/secure-use.md): minimum token permissions and unreliable masking of transformed secrets.
- [Node.js TLS documentation](https://nodejs.org/api/tls.html): certificate validation and `rejectUnauthorized`.

## Run the gates

```bash
PYTHONPATH=src python -m falsum check-scenarios data/draft-scenarios.json
PYTHONPATH=src python -m falsum export-scenarios data/draft-scenarios.json --split train --out /tmp/triplets.jsonl
```

The first command reports 12 cases across 5 categories and correctly shows `reviewed: 0`, `pinned_sources: 0`, `submission_ready: false`. The second **must fail** until the selected cases are reviewed and actual archived source bytes match their declared SHA-256 digests. The exporter never treats mere HTTPS links, `review_status`, or syntactically valid hashes as proof of external acceptance.

## Splits and claims

The 12 cases are separated by source and rule family to prevent obvious train/validation/holdout leakage: 6 train, 4 validation, 2 holdout. The holdout is a *designated future split*, not a credible model benchmark with only two cases. No final accuracy or confidence intervals can be claimed.

We do not submit these examples to Anjoman. Independent domain review must establish the exact source wording, environment, technical truth, plausibility of both answers, group assignment, and whether the curator accepts the examples. Additional primary-source snapshots and diverse review cases are required before training.

All production secrets are omitted or replaced by unmistakably fake placeholders. A label such as `finding` describes the **hypothetical scenario's stipulated facts**, not a discovered incident or exploit of a real organization.

## Formal evidence-promotion gate

To convert draft material into a reviewed case, an independent reviewer must inspect and attest to the case and supporting guidance. For each source, save the original publicly available bytes to a local snapshot under the casebook directory, mark the source `pinned`, specify its relative `snapshot_path`, and include the exact `sha256`. The export gate reads the actual bytes, rejects digest mismatch or escaping paths, and rejects unreviewed cases. This is still insufficient by itself to claim Anjoman eligibility: network upload/curation and eligible state must be independently verified.
