"use strict";
// Execute ONE exact original upstream historical source package in an ephemeral
// GitHub Actions workspace. No fake outputs, no upstream test-suite claims.
// A probe is a focused local reproduction derived from publicly pinned
// upstream test/source evidence, not an independently adjudicated AppSec gold.
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const assert = require("node:assert/strict");

const PROJECTS = new Set([
  "minimist-constructor",
  "json5-proto-data",
  "tough-cookie-null-maps",
  "follow-redirects-custom-headers",
]);
const STATES = new Set(["affected", "fixed"]);
const [project, state, packageRoot, outputPath, commit, sourceBlob, testBlob] = process.argv.slice(2);
if (!PROJECTS.has(project) || !STATES.has(state) ||
    !packageRoot || !outputPath || fs.existsSync(outputPath) ||
    ![commit, sourceBlob, testBlob].every(x=>typeof x==="string" && /^[a-f0-9]{40}$/.test(x))) {
  throw new Error("exact project, source revision, checkout and fresh output required");
}
const pkg = path.resolve(packageRoot);
if (!fs.statSync(pkg).isDirectory()) throw new Error("source is not a real checkout directory");
const marker = "__falsum_private_local_regression_test__";

async function minimist() {
  const parse = require(path.join(pkg, "index.js"));
  assert.equal(typeof parse, "function", "actual historical code was not loaded");
  const normal = parse(["--valid", "7"]);
  const control = normal.valid === 7;
  delete Function.prototype[marker];
  let polluted = false;
  try {
    const argv = parse(["--_.constructor.constructor.prototype." + marker, "verified-source"]);
    polluted = Object.prototype.hasOwnProperty.call(Function.prototype, marker);
    assert.equal(typeof argv, "object");
  } finally {
    delete Function.prototype[marker];
  }
  return {unsafe_observed: polluted, unrelated_safe_control_passed: control};
}

async function json5() {
  const parse = require(path.join(pkg, "lib", "parse.js"));
  assert.equal(typeof parse, "function");
  const normal = parse("{safe:7}");
  const control = normal.safe === 7;
  const doc = parse('{"__proto__":{"falsum_local_only":true}}');
  const safeData = Object.prototype.hasOwnProperty.call(doc, "__proto__") &&
                   Object.getPrototypeOf(doc) === Object.prototype;
  return {unsafe_observed: !safeData, unrelated_safe_control_passed: control};
}

async function cookieJar() {
  const {CookieJar} = require(path.join(pkg, "lib", "cookie.js"));
  assert.equal(typeof CookieJar, "function");
  delete Object.prototype["/notauth"];
  let polluted = false;
  let control = false;
  try {
    const jar = new CookieJar(undefined, {rejectPublicSuffixes:false});
    jar.setCookieSync(
      "Slonser=polluted; Domain=__proto__; Path=/notauth",
      "https://__proto__/admin");
    jar.setCookieSync(
      "Auth=Lol; Domain=google.com; Path=/notauth",
      "https://google.com/");
    polluted = Object.prototype.hasOwnProperty.call(Object.prototype, "/notauth");
    const cookies = jar.getCookiesSync("https://google.com/notauth");
    control = Array.isArray(cookies) && cookies.some(c => c.key === "Auth");
  } finally {
    delete Object.prototype["/notauth"];
  }
  return {unsafe_observed:polluted,unrelated_safe_control_passed:control};
}

async function redirectSensitive() {
  const {http:followingHttp} = require(path.join(pkg, "index.js"));
  assert.equal(typeof followingHttp.get,"function");
  let listening = false;
  let server;
  try {
    server = http.createServer((req,res)=>{
      if(req.url === "/first"){
        res.writeHead(302,{location:"http://127.0.0.2:"+
          server.address().port+"/final"});
        res.end("redirected");
      }else if(req.url === "/final"){
        res.writeHead(200,{"content-type":"application/json"});
        res.end(JSON.stringify({
          extra_sensitive:req.headers["sensitive-a"] || null,
          auth:req.headers.authorization || null,
          safe:req.headers["x-safe-local-control"] || null
        }));
      }else{res.writeHead(404);res.end("not found");}
    });
    await new Promise((resolve,reject)=>{
      server.once("error",reject);
      server.listen(0,"0.0.0.0",resolve);
    });
    listening = true;
    const port=server.address().port;
    const reply=await new Promise((resolve,reject)=>{
      const req=followingHttp.get({
        hostname:"127.0.0.1",
        port,path:"/first",maxRedirects:3,
        sensitiveHeaders:["Sensitive-A"],
        headers:{
          "Sensitive-A":"local-test-only",
          "Authorization":"Bearer local-test-only",
          "X-Safe-Local-Control":"preserve-this"
        }
      },res=>{
        let raw="";
        res.setEncoding("utf8");
        res.on("data",x=>raw+=x);
        res.on("end",()=>{
          try{assert.equal(res.statusCode,200);resolve(JSON.parse(raw));}
          catch(e){reject(e);}
        });
      });
      req.setTimeout(7000,()=>req.destroy(new Error("loopback request timeout")));
      req.once("error",reject);
    });
    const control=reply.safe==="preserve-this" && reply.auth===null;
    return {
      unsafe_observed:reply.extra_sensitive==="local-test-only",
      unrelated_safe_control_passed:control
    };
  }finally{
    if(listening && server){
      await new Promise((resolve,reject)=>
        server.close(err=>err?reject(err):resolve()));
    }
  }
}

async function main() {
  const operations={
    "minimist-constructor":minimist,
    "json5-proto-data":json5,
    "tough-cookie-null-maps":cookieJar,
    "follow-redirects-custom-headers":redirectSensitive,
  };
  const result=await operations[project]();
  const expected_unsafe=state==="affected";
  const evaluation={
    schema_version:1,
    status:"PHASE5V_ACTUAL_ORIGINAL_HISTORICAL_SOURCE_RUNTIME_PROBE",
    project,original_source_revision_role:state,
    original_git_commit:commit,
    original_source_git_blob_sha1:sourceBlob,
    original_upstream_test_git_blob_sha1:testBlob,
    historical_original_source_executed_in_node:true,
    historical_upstream_test_file_authenticated_elsewhere:true,
    full_original_upstream_suite_executed:false,
    unrelated_safe_control_passed:result.unrelated_safe_control_passed,
    unsafe_observed:result.unsafe_observed,
    expected_unsafe_observation:expected_unsafe,
    reproduces_frozen_affected_to_fixed_behavior:
      result.unsafe_observed===expected_unsafe,
    local_loopback_only_if_redirect:project==="follow-redirects-custom-headers",
    no_remote_vulnerability_probe:true,
    no_independent_expert_gold:true,
    no_real_telegraph_network_calls:true,
    no_registered_evaluator:true
  };
  assert.equal(evaluation.unrelated_safe_control_passed,true,
    "original package did not preserve unrelated control behavior");
  assert.equal(evaluation.reproduces_frozen_affected_to_fixed_behavior,true,
    "historical original affected/fixed runtime outcome diverges from preregistration");
  fs.writeFileSync(outputPath,JSON.stringify(evaluation,null,2)+"\n",{flag:"wx"});
  process.stdout.write(JSON.stringify({
    project,state,
    affected_behavior_reproduced:result.unsafe_observed,
    unrelated_control:result.unrelated_safe_control_passed,
    original_source_executed:true
  })+"\n");
}
main().catch(e=>{
  process.stderr.write("PHASE5V ACTUAL ORIGINAL SOURCE FAILED CLOSED: "+
    String(e?.message || e).slice(0,400)+"\n");
  process.exitCode=1;
});
