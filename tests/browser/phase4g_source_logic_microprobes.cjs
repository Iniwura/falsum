"use strict";
/* Isolated reproductions of the narrow branching recorded in public upstream
   Axios/Express fixes. Not execution of either full published package,
   not a customer exploit or an expert-security verdict. */
const assert=require("node:assert/strict");
function isAbsoluteURL(url){return /^([a-z][a-z\d+.-]*:)?\/\//i.test(url);}
function combineURLs(baseURL,relativeURL){
  return relativeURL ? baseURL.replace(/\/?\/$/, "")+"/"+relativeURL.replace(/^\/+/, "") : baseURL;
}
function buildFullPath(baseURL,requestedURL,allowAbsoluteUrls){
  const relative=!isAbsoluteURL(requestedURL);
  if(baseURL&&(relative||allowAbsoluteUrls===false)){
    return combineURLs(baseURL,requestedURL);
  }
  return requestedURL;
}
// Scope is only the historic authority-prefix/encoding decision visible in
// Express's exact pinned lib/response.js change. Percent encoder below tests
// backslash behavior, NOT a full copy of encodeurl.
const schemaAndHostRegExp=/^(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?\/\/[^\\\/\?]+/;
function locationSlashDecision(value){
  const match=schemaAndHostRegExp.exec(value);
  const position=match?match[0].length+1:0;
  const prefix=value.slice(0,position);
  const remainder=value.slice(position).replace(/\\/g,"%5C");
  return prefix+remainder;
}
const base="https://api.example/v1",requested="https://elsewhere.test/x";
const disabled=buildFullPath(base,requested,false);
const defaultAllowed=buildFullPath(base,requested,undefined);
assert.notEqual(disabled,requested);
assert.equal(disabled,"https://api.example/v1/https://elsewhere.test/x");
assert.equal(defaultAllowed,requested);
const authority="http://google.com\\@apple.com";
assert.equal(locationSlashDecision(authority),authority);
const pathSlash="https://google.com/foo\\bar";
assert.equal(locationSlashDecision(pathSlash),"https://google.com/foo%5Cbar");
const result={
  status:"PHASE4G_SOURCE_DERIVED_NODE_MICROPROBE_NOT_UPSTREAM_PACKAGE_EXECUTION",
  checked_author_logic_decisions:4,
  axios_absolute_disabled:disabled,
  axios_absolute_default:defaultAllowed,
  express_authority_first_backslash_preserved:true,
  express_path_backslash_encoded:true,
  upstream_packages_executed:false,
  network_security_certified:false,
  independent_expert_labels:0,
};
console.log(JSON.stringify(result,null,2));
