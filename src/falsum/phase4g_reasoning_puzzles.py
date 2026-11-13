"""Phase 4G: harder source-specific reasoning questions, not new expert labels.

Distinct from the simple Phase 3F/4E question set. Fourteen ORIGINAL
researcher-written conditions on seven ALREADY studied public patches, each
with two plausible explanations and both presentation orders. Not a fresh
holdout, no private Anjoman data, no runtime evaluator and no expert gold.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from .phase3f_multifamily_material import PINS, STATUS as SOURCE_STATUS

STATUS = "PHASE4G_FOURTEEN_CODE_SPECIFIC_PUBLIC_RESEARCH_SCENARIOS_NOT_GOLD"
GITHUB = "https://github.com/"
PROBE_STATUS = "AUTHOR_MICROPROBES_NOT_UPSTREAM_EXECUTION"
CUE = re.compile(r"\b(?:any|every|guarantees|regardless|cannot|automatically|sufficient|need not)\b|no evidence|already inside|needs no", re.I)

# Original order of each two answers is deliberate; never export author_correct
# as an externally approved label. Both candidates refer to the same context.
# The source code and original regression test, not phrasing, should decide.
SPECS = (
 ("requests-https-prepared", "real-requests-proxy-auth",
  "rebuild_proxies receives an HTTPS PreparedRequest and a proxy URL with username and password. What does this function place in the prepared request headers?",
  "It leaves Proxy-Authorization off that HTTPS request, while the proxy adapter may handle authentication separately.",
  "It adds Proxy-Authorization to that HTTPS request, while a separate adapter may also handle authentication.", "A",
  "if not scheme.startswith('https')", "requests/sessions.py", "tests/test_requests.py"),
 ("requests-http-prepared", "real-requests-proxy-auth",
  "rebuild_proxies receives an HTTP PreparedRequest and a credentialed proxy configuration. What is the relevant branch effect?",
  "It leaves Proxy-Authorization to the adapter even though this request's scheme is HTTP.",
  "It sets Proxy-Authorization for the HTTP request if the resolved proxy credentials are available.", "B",
  "http and username and password", "requests/sessions.py", "tests/test_requests.py"),
 ("jinja-absent-attribute", "real-jinja-attr-sandbox",
  "On the patched Jinja attr filter, an object's requested attribute is absent, and hasattr also fails. Does item-key fallback run?",
  "The filter returns an undefined value before environment.getattr, avoiding item-key fallback for that lookup.",
  "The filter calls environment.getattr first; item-key fallback is attempted before undefined is returned.", "A",
  "getattr_static -> hasattr -> undefined", "src/jinja2/filters.py", "tests/test_security.py"),
 ("jinja-existing-attribute", "real-jinja-attr-sandbox",
  "On the patched Jinja attr filter, an attribute exists. Which lookup path controls a sandboxed environment?",
  "The filter returns raw getattr and then applies a separate filter-local safety check.",
  "The filter calls environment.getattr, delegating attribute safety to the environment's sandbox policy.", "B",
  "return environment.getattr(obj, name)", "src/jinja2/filters.py", "tests/test_security.py"),
 ("axios-absolute-disabled", "real-axios-absolute-baseurl",
  "The backported buildFullPath receives baseURL='https://api.example/v1', requestedURL='https://elsewhere.test/x', allowAbsoluteUrls=false. What branch runs?",
  "It returns the absolute requested URL because the requested string contains a URL scheme.",
  "It combines baseURL and the requested string because the explicit false flag activates that branch.", "B",
  "baseURL and (relative or allowAbsoluteUrls === false)", "lib/core/buildFullPath.js", "test/specs/core/buildFullPath.spec.js"),
 ("axios-absolute-default", "real-axios-absolute-baseurl",
  "The same helper receives baseURL='https://api.example/v1', requestedURL='https://elsewhere.test/x' but allowAbsoluteUrls is omitted. What is returned?",
  "It returns the requested absolute URL; configuring baseURL alone does not override this default path.",
  "It combines baseURL and the absolute target; configuring baseURL activates the default join branch.", "A",
  "absolute + allowAbsoluteUrls undefined -> requestedURL", "lib/core/buildFullPath.js", "test/specs/core/buildFullPath.spec.js"),
 ("starlette-prefix-sibling", "real-starlette-commonprefix-traversal",
  "The static root is /app/static and the candidate real path is /app/static_private/info. What changes between string commonprefix and patched commonpath?",
  "The string-prefix test can admit the sibling; patched commonpath recognizes a different directory and rejects it.",
  "The string-prefix test rejects the sibling, while patched commonpath treats it as beneath the static root.", "A",
  "commonprefix may equal root; commonpath equals /app", "starlette/staticfiles.py", "tests/test_staticfiles.py"),
 ("starlette-real-child", "real-starlette-commonprefix-traversal",
  "The static root is /app/static and the real regular file is /app/static/index.html. Does the patched path containment gate exclude it?",
  "It excludes the child when comparing paths with commonpath and continues without a file response.",
  "It accepts the child at the containment gate because commonpath matches the root; file existence is checked next.", "B",
  "commonpath(child, root) == root", "starlette/staticfiles.py", "tests/test_staticfiles.py"),
 ("urllib3-default-lowercase", "real-urllib3-redirect-header-case",
  "On the patched PoolManager, a cross-host redirect uses default Retry stripping and a header key 'authorization'. What happens to the key?",
  "The cross-host loop lowercases header names for comparison and removes the lower-case credential key.",
  "The cross-host loop uses title-cased default keys and retains the lower-case credential key.", "A",
  "header.lower() in remove_headers_on_redirect", "src/urllib3/poolmanager.py", "test/with_dummyserver/test_poolmanager.py"),
 ("urllib3-custom-strip-list", "real-urllib3-redirect-header-case",
  "On the patched PoolManager, Retry(remove_headers_on_redirect=['X-API-Secret']) receives lowercase 'authorization' and 'x-api-secret' during a cross-host redirect. Which stays?",
  "The Authorization key is still stripped by the implicit default, while x-api-secret follows the custom list.",
  "The Authorization key stays because the supplied custom list replaces the default; x-api-secret is stripped.", "B",
  "custom Retry list replaces default remove_headers_on_redirect", "src/urllib3/poolmanager.py", "test/with_dummyserver/test_poolmanager.py"),
 ("django-long-input", "real-django-intcomma-recursive-dos",
  "The old intcomma branch formats an unusually long digit-only input; the fix uses a single reverse-substitution pass. Which algorithm has the recursive depth risk?",
  "The old recursive formatter can exhaust call depth, while the patched substitution is nonrecursive for the input.",
  "The patched substitution recurses over each comma insertion, while the old formatter uses a single pass.", "A",
  "old recursive intcomma, patched re.sub once", "django/contrib/humanize/templatetags/humanize.py", "tests/humanize_tests/tests.py"),
 ("django-three-digit-regression", "real-django-intcomma-recursive-dos",
  "In the exact historical fixed intcomma branch, use_l10n=False and input '123'. What would its reverse-substitution expression output before the later correction?",
  "It yields '123', since three digits are not grouped by the new reverse-substitution expression.",
  "It yields ',123': the group substitution appends a comma before reversing the three-digit result.", "B",
  "r'\\d{3}' with trailing comma produces leading comma after reverse", "django/contrib/humanize/templatetags/humanize.py", "tests/humanize_tests/tests.py"),
 ("express-authority-backslash", "real-express-malformed-redirect-host",
  "The historical Express location patch handles 'http://google.com\\\\@apple.com'. What does its authority-prefix slicing do to the first backslash?",
  "It preserves the first backslash in the authority-like prefix, keeping the Location host parser relevant.",
  "It percent-encodes the first backslash before completing the authority-prefix slicing step.", "A",
  "schemaAndHostRegExp prefix + one delimiter, then encode remainder", "lib/response.js", "test/res.location.js"),
 ("express-path-backslashes", "real-express-malformed-redirect-host",
  "The same Express location patch receives 'https://google.com/foo\\\\bar'. What does it do with the path backslash?",
  "It preserves that path backslash because the prefix regex covers the full requested URL path.",
  "It percent-encodes that path backslash because the encoding resumes after the authority prefix.", "B",
  "encodeUrl(loc.slice(pos)) after authority", "lib/response.js", "test/res.location.js"),
)

def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def keyword_choice(a: str, b: str) -> str:
    """Deliberately weak, position-biased baseline from internal audit #32."""
    ca, cb = len(CUE.findall(a)), len(CUE.findall(b))
    return "A" if ca <= cb else "B"

def validate_source(source: dict) -> dict:
    if not isinstance(source, dict) or any([
        source.get("status") != SOURCE_STATUS,
        source.get("schema_version") != 1,
        source.get("review_cases") != 7,
        source.get("external_source_revisions_verified") != 8,
        source.get("external_source_and_test_file_blob_pairs_verified") != 8,
        source.get("independent_human_labels") != 0,
        source.get("registered_evaluator") is not False,
        source.get("research_only") is not True,
        source.get("network_eligible") is not False,
    ]):
        raise ValueError("missing prior verified seven-family research-only source")
    original = source.get("review_packets")
    if not isinstance(original, list) or len(original) != 7:
        raise ValueError("seven original source records required")
    index = {x.get("packet_id"): x for x in original}
    if len(index) != 7:
        raise ValueError("duplicate source identity")
    for ident, repo, commit, src_blob, test_blob in PINS:
        row = index.get(ident)
        if not isinstance(row, dict) or (
            row.get("repository"), row.get("fix_commit"),
            row.get("source_post_fix_git_blob_sha1"),
            row.get("regression_test_post_fix_git_blob_sha1"),
        ) != (repo, commit, src_blob, test_blob):
            raise ValueError(f"source/blob provenance mismatch: {ident}")
        if row.get("human_preference") is not None or row.get("training_authorized") is not False:
            raise ValueError("cannot promote original researcher draft into gold")
    return index

def build(source: dict) -> tuple[dict, dict]:
    index = validate_source(source)
    if len(SPECS) != 14 or len({s[0] for s in SPECS}) != 14:
        raise ValueError("exactly 14 original conditions required")
    families = {s[1] for s in SPECS}
    if families != set(index) or any(sum(s[1] == k for s in SPECS) != 2 for k in index):
        raise ValueError("each of seven upstream sources needs two research conditions")
    content = []
    author_correct = {}
    for ident, parent, question, a, b, correct, observation, src_file, test_file in SPECS:
        original = index[parent]
        if not all(isinstance(x, str) and len(x) > 35 for x in (question, a, b)):
            raise ValueError("trivial condition or candidate")
        if correct not in ("A", "B") or a == b:
            raise ValueError("author question answer positions malformed")
        if original.get("source_file") != src_file or original.get("regression_test_file") != test_file:
            raise ValueError("source/test path mismatch")
        choices = [{"position": k, "text": txt, "sha256": digest(txt)} for k, txt in (("A",a),("B",b))]
        reversed_choices = [
            {"position": "A", **{z: v for z,v in choices[1].items() if z != "position"}},
            {"position": "B", **{z: v for z,v in choices[0].items() if z != "position"}},
        ]
        content.append({
            "case_id": ident, "source_case_id": parent,
            "upstream_repository": original["repository"],
            "fix_commit": original["fix_commit"],
            "source_file_url": original["source_url"],
            "regression_test_file_url": original["test_url"],
            "advisory_url": original["advisory_url"],
            "question": question,
            "researcher_observation_to_challenge": observation,
            "presentations": [
                {"variant": "original", "candidate_answers": choices,
                 "expert_label": None, "model_score": None},
                {"variant": "swapped", "candidate_answers": reversed_choices,
                 "expert_label": None, "model_score": None},
            ],
            "expert_label": None, "real_app_exploited": False,
            "independent_human_reviewer_verified": False,
            "trainable": False, "network_eligible": False,
            "execution_status": PROBE_STATUS,
        })
        author_correct[ident] = correct
    baseline_hits = sum(
        keyword_choice(item["presentations"][0]["candidate_answers"][0]["text"],
                       item["presentations"][0]["candidate_answers"][1]["text"])
        == author_correct[item["case_id"]] for item in content
    )
    # Unlike the original 7/7 wording shortcut, the weak heuristic must not
    # agree with all AUTHOR hypotheses. This does not prove case difficulty.
    if baseline_hits >= 12:
        raise ValueError("obvious lexical shortcut remains; redesign candidate text")
    public = {
        "schema_version": 1, "status": STATUS,
        "intent": "SECURITY_REVIEW_GENERAL",
        "source_verified_upstream_projects": 7,
        "previously_studied_public_source_cases": 7,
        "new_author_written_reasoning_conditions": 14,
        "position_swapped_display_conditions": 28,
        "new_independent_human_gold_labels": 0,
        "new_anjoman_eligible_rows": 0,
        "actual_model_evaluations_on_this_set": 0,
        "network_registered_evaluator": False,
        "source_exploitability_certified": False,
        "blind_project_holdout": False,
        "author_hypotheses_are_not_gold": True,
        "source_report_sha256": digest(json.dumps(source,sort_keys=True,separators=(",",":"))),
        "cases": content,
        "warning": ("Previously studied public upstream fixes, 14 new AUTHOR-WRITTEN "
          "research scenarios, 28 display positions. The researcher observations "
          "and miniature probes are neither independent expert labels nor actual "
          "upstream package execution. No trained-model improvement is claimed."),
    }
    diagnostic = {
        "schema_version": 1, "status": "PHASE4G_WORDING_HEURISTIC_VS_AUTHOR_HYPOTHESES_NOT_ACCURACY",
        "cases": 14, "author_A_positions": sum(v=="A" for v in author_correct.values()),
        "author_B_positions": sum(v=="B" for v in author_correct.values()),
        "language_shortcut_author_agreements": baseline_hits,
        "language_shortcut_on_14_cases_is_not_security_accuracy": True,
        "independent_ground_truth": False,
        "model_quality_improvement": None,
        "method": "choose fewer absolute/guarantee words; tie defaults to A",
    }
    return public, diagnostic

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--diagnostic", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        if a.out == a.diagnostic or any(x.exists() or x.is_symlink()
              for x in (a.out,a.diagnostic)):
            raise ValueError("refuse overwrite or alias of outputs")
        public, diagnostic = build(json.loads(a.source.read_text(encoding="utf-8")))
        for path, item in ((a.out,public),(a.diagnostic,diagnostic)):
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(item, indent=2, sort_keys=True)+"\n",encoding="utf-8")
        print(json.dumps({k:v for k,v in diagnostic.items() if k != "method"},indent=2))
        return 0
    except (ValueError,TypeError,KeyError,OSError) as e:
        p.exit(1, "FALSUM PHASE4G RESEARCH BLOCKED: " + str(e) + "\n")

if __name__ == "__main__":
    raise SystemExit(main())
