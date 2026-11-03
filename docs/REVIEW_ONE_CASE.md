# Review one public security case

**Independent developers:** We are looking for original, source-backed security assessments for FALSUM's Telegraph Season II Evaluators entry. There are seven public upstream fixes below. Pick **one**, read its exact fix and regression test, then submit an assessment through the normal GitHub form. **A, B, and ABSTAIN** are all valid conclusions.

[**Submit an independent review on GitHub**](https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml)

You do **not** need to install FALSUM, use a wallet, edit JSON, fetch an Actions artifact, or use hidden Anjoman evaluation prompts. Simply choose a case, read its primary code and test, and write what the evidence actually establishes. Include line-specific immutable links using `#L12-L25` at the end of the source/test URLs. State what you cannot verify about a deployed application.

**Fairness:** All candidate answers below were written by FALSUM researchers, not a working model. **No recommended answer, historical model rank, training label or hidden benchmark answer is supplied here.** Neither answer may be fully correct. All seven projects were previously researched; they are not a fresh blinded security holdout. Your submitted GitHub review is a public claim requiring separate expert assessment, **not** an automatically accepted training label, evaluator certification, paid endorsement, or Telegraph contribution. No private keys, production secrets, exploit payloads or unannounced vulnerabilities should be published.

## Choose one case

### 1. Requests: proxy authentication across HTTPS redirects

**Case:** `real-requests-proxy-auth`. **Question:** The historical repair concerns Proxy-Authorization during HTTPS redirects. What conditions are required to apply this finding to a specific caller?

**A:** The patch highlights a credentialed-proxy plus HTTPS-redirect boundary. Verify that both occur for an affected installed version and that secrets reach a redirect before escalating from a source-risk candidate.

**B:** Any use of requests.get with allow_redirects=True leaks proxy credentials because redirects automatically reveal passwords. A proxy password and a real HTTPS redirect path need not be established.

**Primary evidence:** [Affected source and fix](https://github.com/psf/requests/blob/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5/requests/sessions.py) · [Regression test](https://github.com/psf/requests/blob/74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5/tests/test_requests.py) · [Published advisory](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q).

### 2. Jinja: sandbox attr-filter behavior

**Case:** `real-jinja-attr-sandbox`. **Question:** The published Jinja attr-filter sandbox fix changes security checks. Does passing an untrusted variable into a fixed template prove the bypass?

**A:** A user-controlled variable is sufficient to trigger the historical attr filter sandbox escape in any otherwise fixed server-side template. No evidence of attacker-controlled template source is needed.

**B:** An attacker-controlled template source and affected sandbox attr path must be established. Variable values in a fixed template alone do not prove this particular sandbox-escape precondition.

**Primary evidence:** [Affected source and fix](https://github.com/pallets/jinja/blob/065334d1ee5b7210e1a0a93c37238c86858f2af7/src/jinja2/filters.py) · [Regression test](https://github.com/pallets/jinja/blob/065334d1ee5b7210e1a0a93c37238c86858f2af7/tests/test_security.py) · [Published advisory](https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7).

### 3. Axios: absolute URLs and baseURL

**Case:** `real-axios-absolute-baseurl`. **Question:** The Axios patch changes absolute URL handling despite baseURL. How should the caller reason about absolute targets from untrusted input?

**A:** Configuring baseURL guarantees an allowlist for every absolute URL even if a downstream client accepts attacker-controlled absolute targets. The added option cannot affect the request destination.

**B:** An absolute supplied URL can override the intended baseURL depending on version and allowAbsoluteUrls configuration. Inspect the actual client options, target control and network behavior; don't infer SSRF solely from having a baseURL.

**Primary evidence:** [Affected source and fix](https://github.com/axios/axios/blob/02c3c69ced0f8fd86407c23203835892313d7fde/lib/core/buildFullPath.js) · [Regression test](https://github.com/axios/axios/blob/02c3c69ced0f8fd86407c23203835892313d7fde/test/specs/core/buildFullPath.spec.js) · [Published advisory](https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6).

### 4. Starlette: static file directory containment

**Case:** `real-starlette-commonprefix-traversal`. **Question:** Starlette changed the static root check from lexical commonprefix to path-aware commonpath. What deployment evidence is needed?

**A:** A lexically shared filename prefix is not proof of a contained path. Check the installed historical StaticFiles behavior, a reachable route and a readable sibling sharing the root prefix before claiming a real traversal exposure.

**B:** String commonprefix correctly enforces filesystem directory ancestry. Any sibling path beginning with the same letters is already inside the static root and needs no path-aware containment check.

**Primary evidence:** [Affected source and fix](https://github.com/Kludex/starlette/blob/1797de464124b090f10cf570441e8292936d63e3/starlette/staticfiles.py) · [Regression test](https://github.com/Kludex/starlette/blob/1797de464124b090f10cf570441e8292936d63e3/tests/test_staticfiles.py) · [Published advisory](https://github.com/Kludex/starlette/security/advisories/GHSA-v5gw-mw7f-84px).

### 5. urllib3: cross-origin redirect header casing

**Case:** `real-urllib3-redirect-header-case`. **Question:** urllib3 changed removal of authorization headers on cross-origin redirects. Does header casing matter in the historical path?

**A:** Cross-origin redirect handling that removes exactly cased Authorization is already sufficient for every header spelling, so casing and redirect configuration cannot affect credential handling.

**B:** Historically a differently cased authorization header could avoid exact-case removal. Verify a credential-bearing caller, redirect destination, actual casing and stripping policy; a generic redirect alone does not prove a leak.

**Primary evidence:** [Affected source and fix](https://github.com/urllib3/urllib3/blob/adb358f8e06865406d1f05e581a16cbea2136fbc/src/urllib3/poolmanager.py) · [Regression test](https://github.com/urllib3/urllib3/blob/adb358f8e06865406d1f05e581a16cbea2136fbc/test/with_dummyserver/test_poolmanager.py) · [Published advisory](https://github.com/advisories/GHSA-gwvm-45gx-3cf8).

### 6. Django: recursive numeric formatting

**Case:** `real-django-intcomma-recursive-dos`. **Question:** The Django humanize intcomma patch changes recursive formatting of very long numbers. Does any ordinary call constitute a demonstrated DoS?

**A:** The relevant boundary involves unusually long, effectively unbounded numeric input reaching the affected formatter. Establish attacker control, effective limits and installed version; ordinary bounded formatting is not a demonstrated resource-exhaustion attack.

**B:** Using the intcomma filter on even a fixed short numeric string is sufficient evidence of an attacker-triggerable recursive DoS, regardless of request input control or numeric length limits.

**Primary evidence:** [Affected source and fix](https://github.com/django/django/blob/55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9/django/contrib/humanize/templatetags/humanize.py) · [Regression test](https://github.com/django/django/blob/55519d6cf8998fe4c8f5c8abffc2b10a7c3d14e9/tests/humanize_tests/tests.py) · [Published advisory](https://github.com/advisories/GHSA-xxj9-f6rv-m3x4).

### 7. Express: malformed redirect host validation

**Case:** `real-express-malformed-redirect-host`. **Question:** Express changed redirect Location URL handling for malformed inputs. When can an application-level host allowlist be bypassed?

**A:** Compare the actual allowlist parser and emitted Location encoding, especially malformed attacker-controlled URLs. A parser disagreement may affect a caller, but does not prove all res.redirect uses are unsafe.

**B:** Any res.redirect invocation bypasses every host allowlist by default. Whether the requester controls the target or the two parsers disagree on malformed URLs cannot change this conclusion.

**Primary evidence:** [Affected source and fix](https://github.com/expressjs/express/blob/0b746953c4bd8e377123527db11f9cd866e39f94/lib/response.js) · [Regression test](https://github.com/expressjs/express/blob/0b746953c4bd8e377123527db11f9cd866e39f94/test/res.location.js) · [Published advisory](https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc).

## After you choose

[**Open the review form**](https://github.com/Iniwura/falsum/issues/new?template=independent-seven-review.yml). Select your case and A, B or ABSTAIN. Provide source/test exact line links, original security reasoning and deployment uncertainties. An independent third party will still need to assess the substance, reviewer expertise, possible conflicts and reproducibility before any training or evaluation use is considered.

**Current independently accepted reviewer labels: 0.** The existing 20 Anjoman-eligible evaluation pairs are a different signed contribution and are never disclosed by this page. The separate recorded-model failure is documented in [Phase 3V](PHASE3V.md); it was produced on already-studied families and is **not** a claimed corrected evaluator.
