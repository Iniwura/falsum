"use strict";
/* Compare real pinned Axios 0.x URL helpers. NO outgoing HTTP request. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const root = process.argv[2];
const output = process.argv[3];
if (!root || !output || fs.existsSync(output)) {
  throw new Error("provide evidence root and new report path, refusing overwrite");
}
const manifest = JSON.parse(fs.readFileSync(path.join(root, "MANIFEST.json"), "utf8"));
if (manifest.status !== "PINNED_PUBLIC_AXIOS_SOURCE_FOR_LOCAL_BEHAVIOR_AUDIT" ||
    manifest.network_eligible !== false || manifest.has_human_security_review !== false ||
    manifest.proves_deployed_exploitability !== false ||
    manifest.parent_commit !== "8603e677c09fb81bd106999c194308dd230bc596" ||
    manifest.fix_commit !== "02c3c69ced0f8fd86407c23203835892313d7fde") {
  throw new Error("pinned source materialization is untrusted");
}
const before = require(path.resolve(root, "parent/lib/core/buildFullPath.js"));
const after = require(path.resolve(root, "fixed/lib/core/buildFullPath.js"));
const base = "https://trusted.example.invalid/api/";
const untrusted = "https://other.example.invalid/private";
const relative = "v1/users";
const tests = {
  historical_absolute_overrides_base: before(base, untrusted),
  fixed_default_absolute_still_overrides_base: after(base, untrusted),
  fixed_allow_true_absolute_overrides_base: after(base, untrusted, true),
  fixed_allow_false_absolute_confined_to_base_path: after(base, untrusted, false),
  fixed_relative_url_joins_base: after(base, relative, false),
  fixed_no_base_absolute_remains_absolute_even_with_false: after(undefined, untrusted, false),
};
assert.equal(tests.historical_absolute_overrides_base, untrusted);
assert.equal(tests.fixed_default_absolute_still_overrides_base, untrusted);
assert.equal(tests.fixed_allow_true_absolute_overrides_base, untrusted);
assert.notEqual(tests.fixed_allow_false_absolute_confined_to_base_path, untrusted);
assert.ok(tests.fixed_allow_false_absolute_confined_to_base_path.startsWith(base));
assert.equal(tests.fixed_relative_url_joins_base, base + relative);
assert.equal(tests.fixed_no_base_absolute_remains_absolute_even_with_false, untrusted);
const result = {
  schema_version: 1,
  status: "REAL_SOURCE_AXIOS_URL_ROUTING_TESTS_PASSED",
  tests: 6,
  source_parent: manifest.parent_commit,
  source_fixed: manifest.fix_commit,
  historical_untrusted_absolute_bypasses_base: true,
  fixed_default_still_permits_absolute: true,
  fixed_explicit_allow_false_constrains_with_configured_base: true,
  fixed_false_without_base_does_not_constrain_absolute: true,
  observed: tests,
  no_http_request_sent: true,
  credential_exfiltration_reproduced: false,
  independently_human_reviewed: false,
  eligible_for_network: false,
  caution: "A URL-building source behavior check proves routing-string behavior, NOT an actual Axios HTTP request, SSRF exploit, header forwarding or a safe default in all client paths."
};
fs.mkdirSync(path.dirname(output), {recursive:true});
fs.writeFileSync(output, JSON.stringify(result,null,2)+"\n", {flag:"wx"});
console.log(JSON.stringify({
  status:result.status, checks:result.tests,
  default_allows_absolute:result.fixed_default_still_permits_absolute,
  opt_in_false_constrains_when_base_configured:result.fixed_explicit_allow_false_constrains_with_configured_base,
  independent_reviews:0, network_eligible:false,
},null,2));
