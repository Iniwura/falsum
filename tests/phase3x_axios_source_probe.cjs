"use strict";
/*
 * Phase 3X, Axios source-function counterfactual.
 * Copies of all source files come from immutable upstream commits.
 * No HTTP requests are made and the inspected helper is pure URL construction.
 */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const PRE = "8603e677c09fb81bd106999c194308dd230bc596";
const POST = "02c3c69ced0f8fd86407c23203835892313d7fde";
const EXPECTED = {
  before: {
    "lib/core/buildFullPath.js": "00b2b050a109be125f0837acf643f495981b0680",
    "lib/helpers/isAbsoluteURL.js": "43fea788a8291cb52a5c0f351837c4ddc8b8567f",
    "lib/helpers/combineURLs.js": "7c05d1ab0f7fb980c3df7d9c0052dfa34301c730",
  },
  after: {
    "lib/core/buildFullPath.js": "553cffcb5e26bebe93577adae7c1f73f6cd0f293",
    "lib/helpers/isAbsoluteURL.js": "43fea788a8291cb52a5c0f351837c4ddc8b8567f",
    "lib/helpers/combineURLs.js": "7c05d1ab0f7fb980c3df7d9c0052dfa34301c730",
  },
};

function gitBlobHash(data) {
  return crypto.createHash("sha1")
    .update(Buffer.from("blob " + data.length + "\0", "utf8"))
    .update(data)
    .digest("hex");
}

function load(root, side) {
  assert(root && fs.statSync(root).isDirectory(), "Missing " + side + " upstream checkout");
  for (const [file, expected] of Object.entries(EXPECTED[side])) {
    const full = path.resolve(root, file);
    assert(full.startsWith(path.resolve(root) + path.sep), "Invalid file path");
    assert.equal(gitBlobHash(fs.readFileSync(full)), expected,
      "Unexpected " + side + " upstream Git blob: " + file);
  }
  return require(path.resolve(root, "lib/core/buildFullPath.js"));
}

function main() {
  const rootBefore = process.env.AXIOS_BEFORE_DIR;
  const rootAfter = process.env.AXIOS_AFTER_DIR;
  assert(rootBefore && rootAfter, "Set AXIOS_BEFORE_DIR and AXIOS_AFTER_DIR");
  const before = load(rootBefore, "before");
  const after = load(rootAfter, "after");

  const base = "https://allowed.example/v1";
  const offOrigin = "https://other.example/transfer";
  const cases = [
    {name:"configured baseURL + absolute target + strict false",
      base, request:offOrigin, allow:false, beforeOrigin:"https://other.example",
      afterOrigin:"https://allowed.example"},
    {name:"configured baseURL + absolute target + default option",
      base, request:offOrigin, allow:undefined, beforeOrigin:"https://other.example",
      afterOrigin:"https://other.example"},
    {name:"configured baseURL + absolute target + explicit true",
      base, request:offOrigin, allow:true, beforeOrigin:"https://other.example",
      afterOrigin:"https://other.example"},
    {name:"configured baseURL + relative target + strict false",
      base, request:"/account", allow:false, beforeOrigin:"https://allowed.example",
      afterOrigin:"https://allowed.example"},
    {name:"missing baseURL + absolute target + strict false",
      base:undefined, request:offOrigin, allow:false,
      beforeOrigin:"https://other.example",afterOrigin:"https://other.example"},
    {name:"configured baseURL + protocol-relative target + strict false",
      base, request:"//other.example/transfer", allow:false,
      beforeOrigin:"https://other.example",afterOrigin:"https://allowed.example"},
  ];
  const observed = cases.map(c => {
    const oldResult = before(c.base, c.request, c.allow);
    const newResult = after(c.base, c.request, c.allow);
    function origin(value) {
      return new URL(value, "https://unused.example").origin;
    }
    const priorOrigin = origin(oldResult);
    const patchedOrigin = origin(newResult);
    assert.equal(priorOrigin, c.beforeOrigin, c.name + ": old origin");
    assert.equal(patchedOrigin, c.afterOrigin, c.name + ": patched origin");
    return {
      case: c.name, requested_target: c.request, configured_baseURL: c.base ?? null,
      allowAbsoluteUrls: c.allow === undefined ? "omitted" : c.allow,
      parent_result: oldResult, patched_result: newResult,
      parent_origin: priorOrigin, patched_origin: patchedOrigin
    };
  });
  assert.equal(observed.filter(c => c.parent_origin !== c.patched_origin).length, 2);
  const report = {
    schema_version:1,
    status:"SOURCE_EXECUTED_AXIOS_TARGETED_BASEURL_COUNTERFACTUAL",
    upstream:"axios/axios",
    parent_commit:PRE,
    fixed_commit:POST,
    primary_source_blobs_verified:true,
    helper_source_blobs_verified:true,
    full_axios_client_or_network_execution:false,
    only_real_pinned_buildFullPath_helper_executed:true,
    tested_scenarios:observed.length,
    changed_origin_cases:2,
    applicability:"This helper-level observation alone is not proof of SSRF or vulnerable deployment.",
    scenarios:observed
  };
  process.stdout.write(JSON.stringify(report,null,2)+"\n");
  if (process.env.PHASE3X_AXIOS_OUT) {
    const out = path.resolve(process.env.PHASE3X_AXIOS_OUT);
    assert(!fs.existsSync(out), "Refuse to overwrite earlier evidence");
    fs.writeFileSync(out,JSON.stringify(report,null,2)+"\n",{flag:"wx"});
  }
}
try { main(); } catch (err) {
  console.error("FALSUM AXIOS PINNED-PROBE FAILED:",err.stack || String(err));
  process.exitCode=1;
}
