# Phase 4N — Correct contributor-wallet status after account screenshot

**November 18, 2026 · SECURITY_REVIEW_GENERAL · evaluation material only**

The operator opened Anjoman's Evaluators page and supplied the full **Privy Wallet public address** from the same signed-in account. The dashboard screenshot displays **20 Eligible** records tied to an account address ending `e4e6`. The separate Smart Wallet in that screenshot is a **different address** and is **not** used for the contribution query.

The address previously published in [bounty #96 /submit](https://github.com/telegraphprotocol/bounties/issues/96#issuecomment-6588168396) is **different** from the operator-shown Privy Wallet. Previous Phase 4K and 4M probes were correct about the **published bounty-comment address**, but they **cannot be interpreted as showing zero rows in the actual signed-in Privy account**.

The new read-only [Phase 4N checker](../src/falsum/phase4n_privy_account_readback.py) queries both Ethereum public addresses using the documented `/api/evalpool/submissions/mine` endpoint. It retains exact Intent filtering, fail-closed pagination and status validation, and preserves separate success/failure indicators for each account. Only aggregate counts, source hashes, timestamps and public-address SHA-256 fingerprints enter its output. No row hashes, private A/B answers, prompts, wallet signatures or credentials are copied.

```bash
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_phase4n_privy_account_readback.py' -v
PYTHONPATH=src python -m falsum.phase4n_privy_account_readback --out phase4n-status-new.json
```

A successful query can confirm the network's current eligible-row count for the operator-supplied **public Privy Wallet**. It does not independently prove the user cryptographically controls the address, that source security labels are expert-verified, that bounty maintainers have accepted the contribution, or that a trained adapter is deployed. The screenshot is user-provided account evidence and must not be misrepresented as an independently authenticated sign-in.

**Original historical observations:** November 2 signed-in dashboard 20 Eligible; November 14 and November 17 old /submit address 0 Eligible; November 17 separate old-address readback also intermittently failed HTTP. These results are not contradictory once the distinct addresses are recognized.

**Real independent public API outcome, November 18:** [Phase 4N GitHub Actions run](https://github.com/Iniwura/falsum/actions/runs/44311491808) completed successfully after the synthetic safeguards. It observed **20 total/20 Eligible** on the public Privy Wallet supplied by the operator and **0 total/0 Eligible** on the mistaken historical bounty wallet. The check confirms the network count on the named wallet; it does not establish legal identity, signed ownership, gold-label correctness or maintainer acceptance. The original address mismatch has been explained; any remaining procedural correction is to update the bounty discussion.

**Next:** Check the actual live Phase 4N [Actions workflow](../.github/workflows/phase4n-privy-readback.yml); if it independently reports 20 for the Privy Wallet, accurately update the H2 judge packet and clarify the address publicly in the bounty/mission thread without re-uploading private evaluation material. If the query fails or disagrees, retain UNKNOWN/difference and seek maintainer clarification. Do not alter the immutable original /submit evidence or falsely claim bounty acceptance.

No demo work is included in this phase.
